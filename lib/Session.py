import fnmatch, os, os.path, pathlib, shlex, sys, time

from Connector import Connector
from FileInfo import FileInfo
from Log import Logger
from SessionUtils import SessionOptions, UFTPError, normalize_path
import GzipConnector, PConnector, Protocol, RSync, Server, Transfer


class Session(object):
    """ UFTP session """
    
    ACTION_CONTINUE = 0
    ACTION_RETRIEVE = 1
    ACTION_STORE = 2
    ACTION_SYNC_TO_CLIENT = 3
    ACTION_SYNC_TO_SERVER = 4
    ACTION_OPEN_SOCKET = 5
    ACTION_CLOSE_DATA = 7
    ACTION_SEND_HASH = 8

    ACTION_END = 99

    MODE_NONE = 0
    MODE_INFO = 1
    MODE_READ = 2
    MODE_WRITE = 3
    MODE_FULL = 4

    _FEATURES = [ "PASV", "EPSV",
              "RANG STREAM", "REST STREAM"
              "MFMT", "MLSD", "MLST", "APPE",
              "MFF Modify;UNIX.mode;"
              "KEEP-ALIVE",
              "ARCHIVE",
              "DPC2_LOGIN_OK",
              "UTF-8"
    ]

    def __init__(self, connector: Connector, job: dict, LOG: Logger):
        self.job = job
        self.control = connector
        self.advertise_host = job.get("ADVERTISE_HOST", None)
        self.LOG = LOG
        self.includes= []
        self.excludes= []
        _dirname = os.path.dirname(job.get('file', ''))
        _home = os.environ['HOME']
        if not os.path.isdir(_home):
            _home = "/"
        if _dirname=='':
            # no base dir set - start in HOME and
            # allow client to "escape" to higher levels
            self.basedir = "/"
            self.current_dir = _home
        else:
            # explicit base directory is set -
            # clients won't be able to go "up" from there
            if not os.path.isabs(_dirname):
                _dirname = os.path.join(_home, _dirname)
            self.basedir = normalize_path(_dirname)
            self.current_dir = self.basedir
        if not os.path.isdir(self.current_dir):
            raise UFTPError("No such directory: %s" % self.current_dir, 550)
        os.chdir(self.basedir)
        self.access_level = self.MODE_FULL
        _acc = job.get("access-permissions", "FULL")
        for (i, acc) in enumerate(["NONE", "INFO", "READ", "WRITE"]):
            if acc==_acc:
                self.access_level = i
                break
        self.data_connectors = []
        self.data = None
        self.portrange = job.get("PORTRANGE", (0, -1, -1))
        self.reset_range()
        self.options = SessionOptions(max_streams=job.get('MAX_STREAMS', 1),
                                      rate_limit=int(job.get("rateLimit", "0")))
        self.options.num_streams = int(job.get('streams', 1))
        self.options.set_encryption(job.get("key", None), job.get("algo", None))
        self.options.compress = job.get("compress", False)
        for f in job.get('UFTP_NOWRITE', []):
            if len(f)>0:
                self.excludes.append(os.environ['HOME'] + "/" + f)
        for f in job.get("excludes", "").split(":"):
            if len(f)>0:
                self.excludes.append(self.makeabs(f))
        for f in job.get("includes", "").split(":"):
            if len(f)>0:
                self.includes.append(self.makeabs(f))
        self.sleep_time = 0

    def init_functions(self):
        self.functions = {
            "BYE": self.shutdown,
            "QUIT": self.shutdown,
            "SYST": self.syst,
            "FEAT": self.feat,
            "NOOP": self.noop,
            "PWD": self.pwd,
            "CWD": self.cwd,
            "CDUP": self.cdup,
            "MKD": self.mkdir,
            "DELE": self.rm,
            "RNFR": self.rename_from,
            "RNTO": self.rename_to,
            "RMD": self.rmdir,
            "PASV": self.pasv,
            "EPSV": self.epsv,
            "LIST": self.list,
            "STAT": self.stat,
            "MLST": self.mlst,
            "MLSD": self.mlsd,
            "SIZE": self.size,
            "RANG": self.rang,
            "REST": self.rest,
            "RETR": self.retr,
            "ALLO": self.allo,
            "STOR": self.stor,
            "APPE": self.appe,
            "MFMT": self.set_file_mtime,
            "MFF": self.set_file_property,
            "TYPE": self.switch_type,
            "KEEP-ALIVE": self.set_keep_alive,
            "OPTS": self.opts,
            "HASH": self.hash,
            "SYNC-TO-CLIENT": self.sync_to_client,
            "SYNC-TO-SERVER": self.sync_to_server,
            "SEND-FILE": self.rcp_send_file,
            "RECEIVE-FILE": self.rcp_receive_file,
            "RCP-STATUS": self.rcp_status,
            "RCP-ABORT": self.rcp_abort,
       }

    def assert_permission(self, requested):
        if self.access_level < requested:
            raise UFTPError("Access denied", 534)

    def assert_access(self, path):
        for excl in self.excludes:
            if fnmatch.fnmatch(path, excl):
                raise UFTPError("Forbidden: %s excluded via %s" % (path, str(self.excludes)), 534)
        if len(self.includes)==0:
            return
        for incl in self.includes:
            if fnmatch.fnmatch(path, incl):
                return
        raise UFTPError("Forbidden: %s not included in  %s" % (path, str(self.includes)), 534)

    def makeabs(self, path):
        _p = path.strip()
        if not os.path.isabs(_p):
            _p = self.current_dir+"/"+_p
        p = normalize_path(_p)
        if not p.startswith(self.basedir):
            raise UFTPError("Forbidden: %s not in %s"%(p, self.basedir), 534)
        return p

    def shutdown(self, _):
        self.close_data()
        return Session.ACTION_END

    def syst(self, _):
        self.control.write_message(Protocol._SYSTEM_REPLY)

    def feat(self, _):
        self.control.write_message("211-Features:")
        for feat in self._FEATURES:
            self.control.write_message(" %s"  % feat)
        if self.options.is_encrypt():
            self.control.write_message(" CRYPTED-%s"  % self.options.algo)
        self.control.write_message(" HASH %s" % self.options.hash_algorithms_info())
        self.control.write_message("211 END")

    def noop(self, params):
        try:
            n = int(params)
            self.options.num_streams = n
            retcode = "222" if n==self.options.num_streams else "223"
            self.control.write_message("%s Opening %d data connections" % (retcode, self.options.num_streams))
        except:
            self.control.write_message("200 OK")

    def cwd(self, params):
        self.assert_permission(Session.MODE_INFO)
        path = self.makeabs(params)
        self.assert_access(path)
        try:
            os.chdir(path)
            self.current_dir = path
            self.control.write_message("200 OK")
        except OSError as e:
            raise UFTPError("Can't cwd to directory: %s" % str(e), 550)

    def cdup(self, _):
        if self.current_dir==self.basedir:
            raise UFTPError("Can't cd up, already at base directory", 534)
        else:
            try:
                os.chdir("..")
                self.current_dir = os.getcwd()
                self.control.write_message("200 OK")
            except OSError as e:
                raise UFTPError("Can't cd up: %s" % str(e), 500)

    def pwd(self, _):
        self.assert_permission(Session.MODE_INFO)
        self.control.write_message("257 \""+os.getcwd()+"\"")

    def mkdir(self, params):
        self.assert_permission(Session.MODE_WRITE)
        path = self.makeabs(params)
        os.mkdir(path)
        self.control.write_message("257 \"%s\" directory created" % path)

    def rm(self, params):
        self.assert_permission(Session.MODE_FULL)
        _path = self.makeabs(params)
        self.assert_access(_path)
        os.unlink(_path)
        self.control.write_message("200 OK")

    def rmdir(self, params):
        self.assert_permission(Session.MODE_FULL)
        _path = self.makeabs(params)
        self.assert_access(_path)
        os.rmdir(_path)
        self.control.write_message("200 OK")

    def rename_from(self, params):
        self.assert_permission(Session.MODE_WRITE)
        _path = self.makeabs(params)
        self.assert_access(_path)
        self.rename_from_path = _path
        self.control.write_message("350 File action OK Please send rename-to")

    def rename_to(self, params):
        self.assert_permission(Session.MODE_WRITE)
        _path = self.makeabs(params)
        self.assert_access(_path)
        if self.rename_from_path is None:
            raise UFTPError("Illegal sequence of FTP commands - must send RNFR first", 503)
        os.rename(self.rename_from_path, _path)
        self.control.write_message("200 OK")

    def pasv(self, _):
        return self.add_data_connection(epsv=False)

    def epsv(self, _):
        return self.add_data_connection()

    def add_data_connection(self, epsv=True):
        if len(self.data_connectors) == self.options.num_streams:
            self.close_data()
        my_host = self.advertise_host if self.advertise_host else self.job['SERVER_HOST']
        self.LOG.debug("Opening data connection listener on %s"% my_host)
        with Server.setup_data_server_socket(my_host, self.portrange, self.control.is_ipv6()) as server_socket:
            my_port = server_socket.getsockname()[1]
            if epsv:
                msg = "229 Entering Extended Passive Mode (|||%s|)" % my_port
            else:
                if self.advertise_host is None:
                    adv = self.control.my_ip()
                else:
                    adv = self.advertise_host
                msg = "227 Entering Passive Mode (%s,%d,%d)" % (adv.replace(".",","), (my_port / 256), (my_port % 256))
            self.control.write_message(msg)
            _data_connector = Server.accept_data(server_socket, self.LOG, self.control.client_ip())
            self.LOG.debug("Accepted %s" % _data_connector.info())
            self.data_connectors.append(_data_connector)
            if len(self.data_connectors) == self.options.num_streams:
                return Session.ACTION_OPEN_SOCKET

    def post_transfer(self, send226=True):
        self.reset_range()        
        if send226:
            self.control.write_message("226 File transfer successful")

    def list(self, params):
        self.assert_permission(Session.MODE_INFO)
        path = "."
        if params:
            path = params
        if path=="-a":
            path = "."
        path = self.makeabs(path)
        return self.send_directory_listing(path, ls_style=True)

    def mlsd(self, params):
        self.assert_permission(Session.MODE_INFO)
        if params:
            path = params
        else:
            path = "."
        path = self.makeabs(path)
        return self.send_directory_listing(path, mlsd=True)

    def send_directory_listing(self, path, mlsd=False, ls_style=False):
        fi = FileInfo(path)
        if not fi.exists() or not fi.is_dir():
            raise UFTPError("Directory does not exist.", 550, Session.ACTION_CLOSE_DATA)
        try:
            file_list = os.listdir(path)
        except OSError as e:
            raise UFTPError("500 Error listing <%s>: %s"% (path, str(e)), 550, Session.ACTION_CLOSE_DATA)
        self.control.write_message("150 OK")
        for p in file_list:
            try:
                fi = FileInfo(os.path.normpath(os.path.join(path,p)))
                if mlsd:
                    self.data.write_message(fi.as_mlist())
                elif ls_style:
                    self.data.write_message(fi.list())
                else:
                    self.data.write_message(fi.simple_list())
            except Exception as e:
                self.LOG.debug("Error listing %s : %s" % (p, str(e)) )
        self.post_transfer()
        return Session.ACTION_CLOSE_DATA

    def stat(self, params):
        self.assert_permission(Session.MODE_INFO)
        if params is None:
            params = ""
        tokens = params.split(" ", 1)
        asFile = tokens[0]!="N"
        if len(tokens)>1:
            path = tokens[1]
        else:
            path = "."
        path = self.makeabs(path)
        fi = FileInfo(path)
        if not fi.exists():
            raise OSError("Directory/file does not exist or cannot be accessed!")
        if asFile or not fi.is_dir():
            file_list = [ fi ]
        else:
            file_list = [ FileInfo(os.path.normpath(os.path.join(path,p))) for p in os.listdir(path) ]
        self.control.write_message("211- Sending file list")
        for f in file_list:
            try:
                self.control.write_message(" %s" % f.simple_list())
            except:
                # don't want to fail here
                pass
        self.control.write_message("211 End of file list")

    def mlst(self,params):
        self.assert_permission(Session.MODE_INFO)
        if params is None:
            params = "."
        path = self.makeabs(params)
        fi = FileInfo(path)
        if not fi.exists():
            raise UFTPError("Directory/file does not exist or cannot be accessed!", 550, Session.ACTION_CLOSE_DATA)
        self.control.write_message("250- Listing %s" % path)
        self.control.write_message(" %s" % fi.as_mlist())
        self.control.write_message("250 End")

    def size(self, params):
        self.assert_permission(Session.MODE_INFO)
        path = self.makeabs(params)
        fi = FileInfo(path)
        if not fi.exists():
            raise UFTPError("Directory/file does not exist or cannot be accessed!", 550)
        else:
            self.control.write_message(msg = "213 %s" % fi.size())

    def set_range(self, offset, number_of_bytes):
        self.offset = offset
        self.number_of_bytes = number_of_bytes

    def reset_range(self):
        self.set_range(0,-1)
        self.have_range = False

    def rang(self, params):
        tokens = params.split(" ")
        try:
            local_offset = int(tokens[0])
            last_byte = int(tokens[1])
        except:
            raise UFTPError("Argument syntax error", 501)
        if local_offset==1 and last_byte==0:
            response = "350 Resetting range"
            self.reset_range()
        else:
            response = "350 Restarting at %s. End byte range at %s" % (local_offset, last_byte)
            num_bytes = last_byte - local_offset
            self.set_range(local_offset, num_bytes)
            self.have_range = True
        self.control.write_message(response)

    def rest(self, params):
        try:
            local_offset = int(params)
        except:
            raise UFTPError("Argument syntax error", 501)
        self.have_range = False
        self.offset = local_offset
        self.control.write_message("350 Restarting at %s." % local_offset)

    def retr(self, params):
        self.assert_permission(Session.MODE_READ)
        path = self.makeabs(params)
        self.assert_access(path)
        fi = FileInfo(path)
        if not fi.can_read():
            raise UFTPError("Directory/file does not exist or cannot be accessed!", 550)
        if self.have_range:
            size = self.number_of_bytes
        else:
            size = fi.size()
            self.number_of_bytes = size - self.offset
        self.file_path = path
        self.control.write_message("150 OK %s bytes available for reading." % size)
        return Session.ACTION_RETRIEVE

    def allo(self, params):
        self.assert_permission(Session.MODE_WRITE)
        if self.have_range:
            # clients may send both RANG and ALLO:
            self.number_of_bytes = int(params)
        else:
            # or just ALLO:
            self.set_range(0, int(params))
        self.control.write_message("200 OK Will read up to %s bytes from data connection." % self.number_of_bytes)

    def stor(self, params):
        self.assert_permission(Session.MODE_WRITE)
        path = self.makeabs(params)
        self.assert_access(path)
        if self.number_of_bytes==-1:
            self.number_of_bytes = sys.maxsize
        self.file_path = path
        pathlib.Path(path).touch()
        self.control.write_message("150 OK")
        return Session.ACTION_STORE

    def appe(self, params):
        self.assert_permission(Session.MODE_WRITE)
        path = self.makeabs(params)
        self.assert_access(path)
        if self.number_of_bytes==-1:
            self.number_of_bytes = sys.maxsize
            self.offset = os.stat(path)['st_size']
        self.file_path = path
        self.control.write_message("150 OK")
        return Session.ACTION_STORE

    def hash(self, params):
        self.assert_permission(Session.MODE_READ)
        path = self.makeabs(params)
        fi = FileInfo(path)
        if not fi.can_read():
            raise UFTPError("Directory/file does not exist or cannot be accessed!", 550)
        if self.have_range:
            size = self.number_of_bytes
        else:
            size = fi.size()
            self.number_of_bytes = size - self.offset
        self.file_path = path
        return Session.ACTION_SEND_HASH

    def sync_to_client(self, params):
        self.assert_permission(Session.MODE_READ)
        path = self.makeabs(params)
        fi = FileInfo(path)
        if not fi.can_read():
            raise OSError("Directory/file does not exist or cannot be accessed!")
        self.file_path = path
        self.control.write_message("200 OK")
        return Session.ACTION_SYNC_TO_CLIENT

    def sync_to_server(self, params):
        self.assert_permission(Session.MODE_WRITE)
        path = self.makeabs(params)
        fi = FileInfo(path)
        if not fi.can_read():
            raise UFTPError("Directory/file does not exist or cannot be accessed!", 550)
        self.file_path = path
        self.control.write_message("200 OK")
        return Session.ACTION_SYNC_TO_SERVER

    def rcp_send_file(self, params):
        self.assert_permission(Session.MODE_READ)
        try:
            path, remote_file, server_spec, passwd = shlex.split(params)
        except ValueError:
            raise UFTPError("Wrong parameter count", 501)
        path = self.makeabs(path)
        fi = FileInfo(path)
        if not fi.can_read():
            raise UFTPError("Directory/file does not exist or cannot be accessed!", 550)
        self.file_path = path
        self.remote_file_spec = (remote_file, server_spec, passwd)
        child_process_id = self.do_launch_transfer(mode="send")
        self.control.write_message("299 OK transfer-process-ID=%s" % child_process_id)

    def rcp_receive_file(self, params):
        self.assert_permission(Session.MODE_WRITE)
        try:
            path, remote_file, server_spec, passwd = shlex.split(params)
        except ValueError:
            raise UFTPError("Wrong parameter count", 501)
        path = self.makeabs(path)
        self.file_path = path
        self.remote_file_spec = (remote_file, server_spec, passwd)
        child_process_id = self.do_launch_transfer(mode="receive")
        self.control.write_message("299 OK transfer-process-ID=%s" % child_process_id)
    
    def rcp_status(self, params):
        self.assert_permission(Session.MODE_INFO)
        pid = params
        try:
            os.kill(pid, 0)
            result = "RUNNING"
        except ProcessLookupError:
            result = "FINISHED"
        except OSError:
            result = "UNKNOWN"
        self.control.write_message("299 %s" % result)

    def rcp_abort(self, params):
        self.assert_permission(Session.MODE_INFO)
        pid = params
        try:
            os.kill(pid, 9)
            result = "ABORTED"
        except ProcessLookupError:
            result = "FINISHED"
        except OSError:
            result = "UNKNOWN"
        self.control.write_message("299 %s" % result)

    def set_file_mtime(self, params):
        self.assert_permission(Session.MODE_WRITE)
        mtime, target = params.split(" ", 2)
        path = self.makeabs(target)
        self.assert_access(path)
        self._set_mtime(path, mtime)
        self.control.write_message("213 Modify=%s; %s" % (mtime, target))

    def _set_mtime(self, path, mtime):
        st_time = time.mktime(time.strptime(mtime, "%Y%m%d%H%M%S"))
        os.utime(path, (st_time,st_time))
    
    def _set_mode(self, path, mode):
        os.chmod(path, int(mode, 8))
        
    def set_file_property(self, params):
        self.assert_permission(Session.MODE_WRITE)
        fact_spec, target = params.split(" ", 2)
        path = self.makeabs(target)
        self.assert_access(path)
        reply = []
        for fact in fact_spec.split(";"):
            if len(fact)==0:
                continue
            key, value = fact.split("=")
            if key.lower()=="modify":
                self._set_mtime(path, value)
            elif key.lower()=="unix.mode":
                self._set_mode(path, value)
            else:
                raise ValueError(f"Not supported: '{key}'")
            reply.append(fact)
        self.control.write_message("213 %s; %s" % (";".join(reply), target))

    def switch_type(self, params):
        if "ARCHIVE"==params.strip():
            self.options.archive_mode = True
        elif "NORMAL"==params.strip():
            self.options.archive_mode = False
        self.control.write_message("200 OK")

    def set_keep_alive(self, params):
        self.options.keep_alive = params.lower() in [ "true", "yes", "1" ]
        self.control.write_message("200 OK")

    def opts(self, params):
        cmd_tokens = params.split(" ", 2)
        option = cmd_tokens[0].upper()
        if len(cmd_tokens)>1:
            value = cmd_tokens[1]
            self.options.set(option, value)
            self.control.write_message("200 %s=%s" % (option, value))
        else:
            self.control.write_message("211-OPTS")
            for o in self.options.get():
                self.control.write_message(" %s" % o)
            self.control.write_message("211 END")

    def open_data_socket(self):
        if self.options.num_streams == 1:
            self.options.BUFFER_SIZE = 65536
            if self.options.is_encrypt():
                import CryptUtil
                self.data = CryptUtil.CryptedConnector(self.data_connectors[0], self.options.key, self.options.algo)
            else:
                self.data = self.data_connectors[0]
            if self.options.compress:
                self.data = GzipConnector.GzipConnector(self.data)
        else:
            self.LOG.debug("Opening parallel data connector with <%d> streams" % self.options.num_streams)
            self.options.BUFFER_SIZE = 16384 # Java version compatibility
            self.data = PConnector.PConnector(self.data_connectors, self.LOG, self.options.key, self.options.algo, self.options.compress)


    def send_hash(self):
        with open(self.file_path, "rb", buffering = self.options.file_read_buffer_size) as f:
            f.seek(self.offset)
            to_send = self.number_of_bytes
            total = 0
            start_time = int(time.time())
            interval_start = start_time
            md = self.options.get_hash_function()
            while total<to_send:
                length = min(self.options.BUFFER_SIZE, to_send-total)
                data = f.read(length)
                if len(data)==0:
                    break
                total = total + len(data)
                md.update(data)
                if (int(time.time())-interval_start)>30:
                    # keep client entertained
                    self.control.write_message("213-")
                    interval_start = int(time.time())
            last_byte = max(0,  self.offset+self.number_of_bytes-1)
            msg = "213 %s %s-%s %s %s" % (self.options.hash_algorithm,
                    self.offset, last_byte,
                    md.hexdigest(), self.file_path)
            self.control.write_message(msg)
            self.post_transfer(send226=False)
            duration = int(time.time()) - start_time
            self.log_usage(True, total, duration, 1, self.options.hash_algorithm)
    
    def _use_sendfile(self):
        return (type(self.data) is Connector) and self.options.use_sendfile()

    def send_data(self):
        to_send = self.number_of_bytes
        total = 0
        start_time = int(time.time())
        if self._use_sendfile():
            self.LOG.debug("Using sendfile()")
            with open(self.file_path, "rb") as f:
                f.seek(self.offset)
                while total<to_send:
                    _sent = os.sendfile(self.data.fileno(), f.fileno(), offset=None, count=to_send-total)
                    if _sent==0:
                        break
                    total = total + _sent
        else:
            with open(self.file_path, "rb", buffering = self.options.file_read_buffer_size) as f:
                f.seek(self.offset)
                total = self.copy_data(f, self.data, to_send)
        if self.options.compress or self.options.is_encrypt():
            self.data.close()
        self.post_transfer()
        if not self.options.keep_alive:
            self.close_data()
        duration = int(time.time()) - start_time
        self.log_usage(True, total, duration)

    def recv_data(self):
        if self.options.archive_mode:
            self.recv_archive_data()
        else:
            self.recv_normal_data()

    def recv_normal_data(self):
        with open(self.file_path, "r+b", buffering = self.options.file_write_buffer_size) as f:
            if not self.have_range:
                try:
                    f.truncate(0)
                except OSError:
                    pass
            f.seek(self.offset)
            reader = self.get_reader()
            start_time = int(time.time())
            total = self.copy_data(reader, f, self.number_of_bytes)
        if not self.options.keep_alive:
            self.close_data()
        duration = int(time.time()) - start_time
        self.post_transfer()
        self.log_usage(False, total, duration)

    def recv_archive_data(self):
        import tarfile
        reader = self.get_reader()
        start_time = int(time.time())
        tar = tarfile.TarFile.open(mode="r|", fileobj=reader)
        counter = 0
        total = 0
        while True:
            entry = tar.next()
            if entry is None:
                break
            self.LOG.debug("Processing tar entry: %s length=%s" % (entry.name, entry.size))
            pathname = self.makeabs(os.path.join(self.file_path , entry.name))
            _d = os.path.dirname(pathname)
            try:
                if not os.path.exists(_d):
                    os.makedirs(_d, exist_ok=True)
            except Exception as e:
                self.LOG.debug("Error creating directory %s: %s"%(_d, str(e)))
            with open(pathname, "wb") as f:
                entry_reader = tar.extractfile(entry)
                if entry_reader is None:
                    # TBD handle links and such?
                    self.LOG.debug("No file returned for %s" % entry.name)
                else:
                    total += self.copy_data(entry_reader, f, entry.size)
            counter+=1
        self.post_transfer()
        if not self.options.keep_alive:
            self.close_data()
        duration = int(time.time()) - start_time
        self.log_usage(False, total, duration, num_files=counter)

    def close_data(self):
        self.options.num_streams = 1
        try:
            self.data.close()
        except:
            pass
        self.data_connectors = []
        self.data = None

    def get_reader(self):
        if self.options.is_encrypt():
            self.number_of_bytes = sys.maxsize
        return self.data

    def copy_data(self, reader, target, num_bytes):
        total = 0
        limit_rate = self.options.rate_limit > 0
        start_time = int(time.time())
        while total<num_bytes:
            length = min(self.options.BUFFER_SIZE, num_bytes-total)
            _data = reader.read(length)
            if len(_data)==0:
                break
            to_write = len(_data)
            write_offset = 0
            while(to_write>0):
                written = target.write(_data[write_offset:])
                write_offset += written
                to_write -= written
            total = total + len(_data)
            if limit_rate:
                self.control_rate(total, start_time)
        return total
    
    def do_sync_to_client(self):
        stats = RSync.Leader(self.data, self.file_path).run()
        msg = "USAGE [sync-to-client] [%s] [%s]" % (stats, self.job['user'])
        self.LOG.info(msg)
        
    def do_sync_to_server(self):
        stats = RSync.Follower(self.data, self.file_path).run()   
        msg = "USAGE [sync-to-server] [%s] [%s]" % (stats, self.job['user'])
        self.LOG.info(msg)
    
    def do_launch_transfer(self, mode):
        pid = Transfer.launch_transfer(self.remote_file_spec, self.file_path, mode,
                                       self.LOG, self.job['user'],
                                       offset=self.offset, length=self.number_of_bytes,
                                       rate_limit=self.options.rate_limit,
                                       number_of_streams=self.options.num_streams,
                                       key=self.options.key,
                                       algo=self.options.algo,
                                       compress=self.options.compress
                                       )
        self.LOG.info("Started server-server transfer, child process PID <%s>" % pid)
        self.reset_range()
        return pid

    def control_rate(self, total, start_time):
        interval = int(time.time() - start_time) + 1
        current_rate = total / interval
        if current_rate < self.options.rate_limit:
            self.sleep_time = int(0.5 * self.sleep_time)
        else:
            self.sleep_time = self.sleep_time + 5
            time.sleep(0.001*self.sleep_time)

    def log_usage(self, send, size, duration, num_files = 1, operation=None):
        if operation is None:
            if send:
                operation = "Sent %d file(s)" % num_files
            else:
                operation = "Received %d file(s)" % num_files
        rate = 0.001*float(size)/(float(duration)+1)
        if rate<1000:
            unit = "kB/sec"
            rate = int(rate)
        else:
            unit = "MB/sec"
            rate = int(rate / 1000)
        msg = "USAGE [%s] [%s bytes] [%s %s] [%s]" % (operation, size, rate, unit, self.job['user'])
        self.LOG.info(msg)

    def run(self):
        self.init_functions()
        if self.options.rate_limit>0:
            _r = int(self.options.rate_limit/(1024*1024))
            if _r==0:
                _r = "<1"
            _lim = "%s MB/sec" % _r
        else:
            _lim = "no"
        if self.options.is_encrypt():
            _crypt = "True (%s)" % self.options.algo
        else:
            _crypt = "False"
        self.LOG.info("Processing UFTP session for <%s : %s : %s>, initial_dir='%s', base='%s', encrypted=%s, compress=%s, ratelimit=%s, persistent=%s" % (
            self.job['user'], self.job['group'], self.control.client_ip(),
            self.current_dir, self.basedir,
            _crypt, self.options.compress, _lim, self.job['_PERSISTENT']
        ))
        while True:
            msg = self.control.read_line()
            if len(msg.strip())==0:
                continue
            params = None
            tokens = msg.split(" ", 1)
            cmd = tokens[0].upper()
            if len(tokens)>1:
                params = tokens[1]
            func = self.functions.get(cmd, None)
            if func:
                try:
                    mode = func(params)
                    if mode==Session.ACTION_RETRIEVE:
                        try:
                            self.send_data()
                        except Exception as e:
                            self.close_data()
                            raise e
                    elif mode==Session.ACTION_STORE:
                        try:
                            self.recv_data()
                        except Exception as e:
                            self.close_data()
                            raise e
                    elif mode==Session.ACTION_OPEN_SOCKET:
                        self.open_data_socket()
                    elif mode==Session.ACTION_CLOSE_DATA:
                        self.close_data()
                    elif mode==Session.ACTION_SEND_HASH:
                        self.send_hash()
                    elif mode==Session.ACTION_SYNC_TO_CLIENT:
                        self.do_sync_to_client()
                    elif mode==Session.ACTION_SYNC_TO_SERVER:
                        self.do_sync_to_server()
                    elif mode==Session.ACTION_END:
                        break
                except UFTPError as ue:
                    self.control.write_message("%s Error processing command '%s': %s" % (ue.error_code, cmd, ue.msg))
                    if ue.action == Session.ACTION_CLOSE_DATA:
                        self.close_data()
                except Exception as e:
                    self.control.write_message("500 Error processing command '%s': %s" % (cmd, str(e)))
                    self.LOG.log_exception()
            else:
                self.control.write_message("502 Command not implemented.")