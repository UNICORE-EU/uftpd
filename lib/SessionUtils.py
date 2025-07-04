from base64 import b64decode
import hashlib
import os.path

def normalize_path(path: str):
    p = os.path.normpath(path)
    # limit number of any leading slashes to "1"
    while p.startswith("//"):
        p = p[1:]
    return p

class UFTPError(Exception):
    def __init__(self, msg: str, error_code = 500, action=0):
        self.msg = msg
        self.error_code = error_code
        self.action = action

class SessionOptions(object):
    """ Options for a UFTP session.
    Some of them can be modified at runtime via the OPTS command """

    def __init__(self, rate_limit = 0, max_streams = 8):
        self._num_streams = 1
        self.max_streams = max_streams
        self.BUFFER_SIZE = 65536
        self.file_read_buffer_size = 16384
        self.file_write_buffer_size = 16384
        self.rate_limit = rate_limit
        self.initial_rate_limit = rate_limit
        self.archive_mode = False
        self.keep_alive = False
        self.key = None
        self.algo = "n/a"
        self.compress = False
        self._hash_algorithm = "MD5"
        self.hash_algorithms = {"MD5": hashlib.md5,
                                "SHA-1": hashlib.sha1,
                                "SHA-256": hashlib.sha256,
                                "SHA-512": hashlib.sha512}
        self.sendfile_enabled = False

    @property
    def num_streams(self):
        return self._num_streams

    @num_streams.setter
    def num_streams(self, num_streams: int):
        if num_streams<=self.max_streams:
            self._num_streams = num_streams
        else:
            self._num_streams = self.max_streams

    def get_hash_function(self):
        return self.hash_algorithms[self._hash_algorithm]()

    @property
    def hash_algorithm(self):
        return self._hash_algorithm

    @hash_algorithm.setter
    def hash_algorithm(self, algo: str):
        algo = algo.upper()
        if not algo in self.hash_algorithms.keys():
            raise ValueError("Unsupported hash algorithm '%s'" % algo)
        self._hash_algorithm = algo

    def hash_algorithms_info(self):
        ret = ""
        for f in self.hash_algorithms.keys():
            if len(ret)>0:
                ret+=";"
            ret+=f
            if f==self.hash_algorithm:
                ret+="*"
        return ret

    def set_encryption(self, key: str, algo: str):
        self.key = key
        if self.key is not None:
            self.key = b64decode(self.key)
            self.algo = algo
            if self.algo is None:
                if len(self.key) in [16+16, 16+24, 16+32]:
                    self.algo = "AES"
                else:
                    self.algo = "BLOWFISH"
                    if len(self.key)>56:
                        raise ValueError("Illegal key length")

    def use_sendfile(self):
        return self.sendfile_enabled and not (self.rate_limit > 0 or self.is_encrypt() or self.compress)

    def is_encrypt(self):
        return self.key is not None

    def get(self):
        """ get a list of the (user-modifiable options)"""
        opts = [
            "RATE_LIMIT %s" % self.rate_limit,
            "FILE_READ_BUFFERSIZE %s" % self.read_buffer_size,
            "FILE_WRITE_BUFFERSIZE %s" % self.write_buffer_size,
            "SENDFILE_ENABLED %s" % self.sendfile_enabled
        ]
        return opts

    def set(self, option: str, value: str):
        """ set named option """
        if "FILE_READ_BUFFER_SIZE"==option:
            self.file_read_buffer_size = self._positive_int(value)
        elif "FILE_WRITE_BUFFER_SIZE"==option:
            self.file_buffer_buffer_size = self._positive_int(value)
        elif "HASH"==option:
            self.hash_algorithm = value
        elif "SENDFILE_ENABLED"==option:
            self.sendfile_enabled = value.lower() in ["true", "1", "yes"]
        elif "KEEP_ALIVE"==option:
            self.keep_alive = value.lower() in ["true", "1", "yes"]
        elif "ARCHIVE"==option:
            self.archive_mode = value.lower() in ["true", "1", "yes"]
        elif "RATE_LIMIT"==option:
            r = self._positive_int(value)
            if self.initial_rate_limit<=0:
                self.rate_limit = self._positive_int(value)
            else:
                self.rate_limit = min(self.initial_rate_limit, r)
        else:
            raise ValueError("Unknown option '%s'" % option)

    def _positive_int(self, value: str):
        i = int(value)
        if i<0:
            raise ValueError("Need positive value")
        return i