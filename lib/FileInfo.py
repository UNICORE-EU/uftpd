import os
from os.path import basename, isdir, exists, normpath
from time import localtime, strftime, time

class FileInfo(object):
    """ file information in various formats """

    def __init__(self, fullpath):
        self.path = normpath(fullpath)

    def _type(self):
        if isdir(self.path):
            return "dir"
        else:
            return "file"

    def _perm(self, empty="", mlst=False):
        perm = ""
        if os.access(self.path, os.R_OK):
            if mlst and self.is_dir():
                perm+="l"
            else:
                perm+="r"
        else:
            perm+=empty
        if os.access(self.path, os.W_OK):
            perm+="w"
        else:
            perm+=empty
        if os.access(self.path, os.X_OK):
            if mlst and self.is_dir():
                perm+="e"
            else:
                perm+="x"
        else:
            perm+=empty
        return perm

    def _lperm(self):
        pass

    def exists(self):
        return exists(self.path)

    def can_read(self):
        return exists(self.path) and os.access(self.path, os.R_OK)

    def is_dir(self):
        return isdir(self.path)

    def size(self):
        return os.stat(self.path).st_size

    def as_mlist(self):
        st = os.stat(self.path)
        if self.path=="/":
            p = self.path
        else:
            p = basename(self.path)
        return "size=%s;modify=%s;type=%s;perm=%s;UNIX.mode=%s; %s" % (st.st_size,
           strftime("%Y%m%d%H%M%S", localtime(st.st_mtime)),
           self._type(),
           self._perm(mlst=True),
           oct(st.st_mode)[2:],
           p
        )

    def list(self):
        """ Linux "ls" style """
        st = os.stat(self.path)
        if isdir(self.path):
            d = "d"
            l = "3"
        else:
            d = "-"
            l = "1"
        if st.st_mtime < int(time())-15811200:
            udate = strftime("%b %d %Y", localtime(st.st_mtime))
        else:
            udate = strftime("%b %d %H:%M", localtime(st.st_mtime))
        return "%s%s------   %s dummy dummy %s %s %s\r" % (d, self._perm("-"),
                                                           l,
                                                           st.st_size,
                                                           udate,
                                                           basename(self.path))

    def simple_list(self):
        st = os.stat(self.path)
        if isdir(self.path):
            d = "d"
        else:
            d = "-"
        if self.path=="/":
            p = self.path
        else:
            p = basename(self.path)
        if len(p)==0:
            p = "."
        return "%s%s %s %s %s" % (d, self._perm("-"), st.st_size,
           1000*int(st.st_mtime),  p)
