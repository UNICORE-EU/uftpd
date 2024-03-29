#
# simplistic logger writing to syslog (or console)
#
from sys import stdout
from syslog import closelog, openlog, syslog, LOG_DEBUG, LOG_ERR, LOG_INFO
import traceback

class Logger(object):

    def __init__(self, verbose=False, use_syslog=True):
        self.verbose = verbose
        self.use_syslog = use_syslog
        if use_syslog:
            openlog("UFTPD")

    def out(self, message):
        print(message)
        stdout.flush()

    def reinit(self, name="UFTPD-worker"):
        if self.use_syslog:
            closelog()
            openlog(name)

    def error(self, message):
        if self.use_syslog:
            syslog(LOG_ERR, str(message))
        else:
            self.out("[ERROR] %s" % str(message))

    def info(self, message):
        if self.use_syslog:
            syslog(LOG_INFO, str(message))
        else:
            self.out("[INFO] %s" % str(message))

    def debug(self, message):
        if not self.verbose:
            return
        if self.use_syslog:
            syslog(LOG_DEBUG, str(message))
        else:
            self.out("[DEBUG] %s" % str(message))
            
    def log_exception(self):
        if not self.verbose:
            return
        self.debug(traceback.format_exc())
        
