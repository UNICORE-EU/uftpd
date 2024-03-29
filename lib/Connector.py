""" Helpers for dealing with control and data connections """

from socket import socket, SHUT_RDWR
from Log import Logger

class Connector(object):

    def __init__(self, client: socket, LOG: Logger, conntype="FTP", binary_mode=False):
        self.client = client
        self.binary_mode = binary_mode
        if binary_mode:
            self._input = client.makefile("rb")
            self._output = client.makefile("wb")
        else:
            self._input = client.makefile("r")
            self._output = client.makefile("w")
        self.LOG = LOG
        self.conntype = conntype;

    def client_ip(self):
        return self.client.getpeername()[0]

    def my_ip(self):
        return self.client.getsockname()[0]

    def info(self):
        return "%s connection with %s" % (self.conntype, self.client.getpeername())
        
    def read_request(self):
        """ reads lines until 'END' """
        lines = []
        try:
            while True:
                msg = self._input.readline(8192)
                if msg.startswith("END"):
                    break
                msg = msg.strip()
                self.LOG.debug("==>  %s" % msg)
                lines.append(msg)
            return lines
        except Exception as e:
            self.LOG.error(e)
            self.close()
        return None

    def read_line(self):
        """Read line from remote
           Returns unicode
        """
        line = self._input.readline(8192)
        if len(line) == 0:
            raise IOError("Socket closed")
        line = line.strip()
        self.LOG.debug("--> %s" % line)
        return line

    def write_message(self, message):
        """ Write message to remote channel and add newline """
        if message is not None:
            try:
                self.LOG.debug("<-- %s" % message.__repr__())
            except:
                pass
            message = message + "\n"
            if self.binary_mode:
                message = message.encode('utf-8')
            self._output.write(message)
            self._output.flush()

    def write(self, data, do_flush=True):
        """ Write all the data to remote channel """
        to_write = len(data)
        write_offset = 0
        while to_write > 0:
            written = self._output.write(data[write_offset:])
            if written is None:
                written = 0
            write_offset += written
            to_write -= written
        if do_flush:
            self._output.flush()

    def read(self, length):
        """ Read data from remote channel """
        return self._input.read(length)

    def cleanup(self):
        try:
            self._input.close()
            self._output.close()
            self.client.close()
        except Exception as e:
            self.LOG.error(e)

    def close(self):
        try:
            try:
                self.LOG.debug("Closing %s" % self.info())
            except:
                pass
            self.client.shutdown(SHUT_RDWR)
            self.client.close()
        except Exception as e:
            self.LOG.error(e)
            
    def flush(self):
        self._output.flush()
