#
# simplistic logger writing to syslog (or console)
#
from sys import stdout
from syslog import closelog, openlog, syslog, LOG_DEBUG, LOG_ERR, LOG_INFO

class Logger(object):

    def __init__(self, verbose=False, use_syslog=True):
        self.verbose = verbose
        self.use_syslog = use_syslog
        if use_syslog:
            openlog("UFTPD")

    def reinit(self):
        if self.use_syslog:
            closelog()
            openlog("UFTPD-worker")

    def error(self, message):
        if self.use_syslog:
            syslog(LOG_ERR, str(message))
        else:
            self.info("[ERROR] %s" % str(message))

    def info(self, message):
        if self.use_syslog:
            syslog(LOG_INFO, str(message))
        else:
            print(message)
            stdout.flush()

    def debug(self, message):
        if not self.verbose:
            return
        if self.use_syslog:
            syslog(LOG_DEBUG, str(message))
        else:
            self.info("[DEBUG] %s" % str(message))
