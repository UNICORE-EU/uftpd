"""
Main UFTPD module

Starts the FTP listener thread, and containing the main loop that listens to
the control socket, and processes control requests
"""

import os
import sys
import threading
import time
import BecomeUser, FTPHandler, Log, Server

#
# the UFTPD version
#
MY_VERSION = "3.0.0-DEV"

# supported Python version
REQUIRED_VERSION = (3, 4, 0)

# how long to wait for transfer client to connect
_REQUEST_LIFETIME = 300

def assert_version():
    """
    Checks that the Python version is correct
    """
    return sys.version_info >= REQUIRED_VERSION

def setup_config(config):
    config['CMD_HOST'] = os.getenv("CMD_HOST", "localhost")
    config['CMD_PORT'] = int(os.getenv("CMD_PORT", "64435"))
    config['SERVER_HOST'] = os.getenv("SERVER_HOST", "localhost")
    config['SERVER_PORT'] = int(os.getenv("SERVER_PORT", "64434"))
    config['SSL_CONF'] = os.getenv("SSL_CONF", None)
    config['ACL'] = os.getenv("ACL", "conf/uftpd.acl")
    config['uftpd.acl'] = []
    config['MAX_STREAMS'] = int(os.getenv("MAX_STREAMS", "1")) # no-op
    config['MAX_CONNECTIONS'] = int(os.getenv("MAX_CONNECTIONS", "8"))
    config['UFTP_KEYFILES'] = os.getenv("UFTP_KEYFILES", ".ssh/authorized_keys:.uftp/authorized_keys").split(":")
    config['UFTP_NOWRITE'] = os.getenv("UFTP_NOWRITE", ".ssh/authorized_keys").split(":")
    config['uftpd.enforce_os_gids'] =  os.getenv("UFTP_ENFORCE_OS_GIDS", "true").lower() in [ "true", "yes", "1" ]
    config['VERBOSE'] = os.getenv("VERBOSE", "false").lower() in [ "true", "yes", "1" ]
    
def parse_request(message):
    request = {}
    for line in message:
        if line.startswith("END"):
            break
        try:
            k, v = line.strip().split("=",1)
            request[k]=v
        except:
            pass
    return request

def init_functions():
    """
    Creates the function lookup table used to map request types
    to the appropriate function
    """
    return {
        "uftp-ping-request": ping,
        "uftp-get-user-info-request": get_user_info, 
        "uftp-transfer-request": add_job,
    }

def ping(request, connector, config, LOG):
    response = """Version: %s
ListenPort: %s
ListenAddress: %s
""" % (
        MY_VERSION,
        config['SERVER_PORT'],
        config['SERVER_HOST']
    )
    return response

def get_user_info(request, connector, config, LOG):
    user = request['user'].strip()
    if user=="root":
        return "500 Not allowed"
    user_cache = config['uftpd.user_cache']
    response = """Version: %s
User: %s
""" % (
        MY_VERSION,
        user
    )
    home = user_cache.get_home_4user(user)
    if home:
        response += "Status: OK\n"
        response += "Home: %s\n" % home
        i = 0   
        for keyfile in config['UFTP_KEYFILES']:
            try:
                with open(os.path.join(home, keyfile), "r") as f:
                    for line in f.readlines():
                        if line.startswith("#"):
                            continue
                        response+="Accepted key %d: %s\n" % (i, line.strip())
                        i+=1
            except:
                pass
    return response

def add_job(request, connector, config, LOG):
    secret = request['secret']
    job_map = config['job_map']
    if job_map.get(secret, None) is not None:
        raise Exception("Duplicate secret - this is not allowed.")
    user = request['user']
    group = request.get('group', "NONE")
    request['group'] = group.split(":")
    request['_LOCK'] = threading.Lock()
    request['_EXPIRES'] = int(time.time())+_REQUEST_LIFETIME
    request['_PIDS'] = []
    job_map[secret] = request
    LOG.info("New transfer request for '%s' groups: %s" % (user, str(group)))
    return "OK::%s" % config['SERVER_PORT']

def cleanup(config, LOG):
    LOG.info("Request cleanup thread started.")
    job_map = config['job_map']
    while True:
        for key in set(job_map.keys()):
            try:
                job = job_map[key]
                lock = job['_LOCK']
                with lock:
                    pids = job['_PIDS']
                    if len(pids)==0:
                        expires = job['_EXPIRES']
                        if time.time() > expires:
                            LOG.info("Removing expired job from '%s'" % job['user'])
                            del job_map[key]
                    else:
                        for pid in pids[:]:
                            (_pid, _status) = os.waitpid(pid, os.WNOHANG)
                            if _pid!=0:
                                pids.remove(pid)
                        if len(pids)==0:
                            LOG.info("Processing request for <%s> finished." % job['user'])
                            del job_map[key]
            except Exception as e:
                LOG.error(e)
        time.sleep(10)

def process(cmd_server, config, LOG):
    """
    Command processing loop. Reads commands from control_in and invokes the
    appropriate command.

        Arguments:
          connector: connection to the auth server
          job_map: map ccontaining transfer requests, keyed by one-time password
          config: configuration (dictionary)
          LOG: logger object
    """
    functions = init_functions()

    while True:
        try:
            connector = Server.accept_command(cmd_server, config, LOG)
            msg = connector.read_request()
            request = parse_request(msg)
            request_type = request.get('request-type', "n/a")
            func = functions.get(request_type, None)
            if not func:
                raise Exception("Unsupported request type '%s'" % request_type)
            try:
                response = func(request, connector, config, LOG)
            except Exception as e:
                LOG.error(e)
                response = "500::Request rejected. Reason: %s" % str(e)
            connector.write_message(response)
            connector.close()
        except Exception as e:
            LOG.error("Error in command loop: %s" % e)
            connector.close()

def main(argv=None):
    """
    Start UFTPD
    """
    if not assert_version():
        raise RuntimeError("Unsupported version of Python! "
                           "Must be %s or later." % str(REQUIRED_VERSION))

    config = {}
    setup_config(config)
    verbose = config["VERBOSE"]
    LOG = Log.Logger(verbose)

    LOG.info("**** UFTPD Version %s starting" % MY_VERSION)

    BecomeUser.initialize(config, LOG)

    job_map = {}
    config['job_map'] = job_map

    cmd_server = Server.setup_cmd_server_socket(config, LOG)

    housekeeping_thread = threading.Thread(target=cleanup,
                                  name="Cleanup",
                                  args=(config, LOG))
    housekeeping_thread.start()

    ftp_server = Server.setup_ftp_server_socket(config, LOG)
    ftp_thread = threading.Thread(target=FTPHandler.ftp_listener,
                                  name="FTPListener",
                                  args=(ftp_server, config, LOG))
    ftp_thread.start()

    LOG.debug("Reading user keys from: %s" % config['UFTP_KEYFILES'])
    LOG.debug("Write protected files : %s" % config['UFTP_NOWRITE'])
    LOG.debug("Max. sessions per job : %s" % config['MAX_CONNECTIONS'])
    
    process(cmd_server, config, LOG)
    return 0

# application entry point
if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)