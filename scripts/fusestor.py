#!/usr/bin/env python

#    Copyright (C) 2006  Andrew Straw  <strawman@astraw.com>
#
#    This program can be distributed under the terms of the GNU LGPL.
#    See the file COPYING.
#

import sys, os, stat, errno
# pull in some spaghetti to make this stuff work without fuse-py being installed
try:
    import _find_fuse_parts
except ImportError:
    pass
import fuse
from fuse import Fuse

import sqlite3


if not hasattr(fuse, '__version__'):
    raise RuntimeError("your fuse-py doesn't know of fuse.__version__, probably it's too old.")

fuse.fuse_python_api = (0, 2)

class MyStat(fuse.Stat):
    def __init__(self):
        self.st_mode = 0
        self.st_ino = 0
        self.st_dev = 0
        self.st_nlink = 0
        self.st_uid = 0
        self.st_gid = 0
        self.st_size = 0
        self.st_atime = 0
        self.st_mtime = 0
        self.st_ctime = 0

class BkupFS(Fuse):
    
    def __init__(self, *args, **kw):
        Fuse.__init__(self, *args, **kw)

    def setbkupdir(self, bkupdir):          
        print("bkupdir:", bkupdir)  
        self.bkupdir = bkupdir

    def getattr(self, path):
        st = MyStat()
        if path == '/':
            st.st_mode = stat.S_IFDIR | 0o755
            st.st_nlink = 2
        else:
            if len(path) > 0 and path[0] == '/':
                path = path[1:]
            fp = os.path.join(self.bkupdir, path)
            if not os.path.exists(fp):
                return -errno.ENOENT
            if os.path.isdir(fp):
                st.st_mode = stat.S_IFDIR | 0o755
            else:
                st.st_mode = stat.S_IFREG | 0o444
            st.st_nlink = 1
            st.st_size = os.path.getsize(fp)
        return st

    def readdir(self, path, offset):
        for r in ['.', '..']:
            yield fuse.Direntry(r)
        if len(path) > 0 and path[0] == '/':
            path = path[1:]
        fp = os.path.join(self.bkupdir, path)
        if os.path.exists(fp):
            for filename in os.listdir(fp):
                yield fuse.Direntry(filename)
        else:
            return -errno.ENOENT
        

    def open(self, path, flags):
        if len(path) > 0 and path[0] == '/':
            path = path[1:]
        fp = os.path.join(self.bkupdir, path)
        if not os.path.exists(fp): 
            return -errno.ENOENT
        accmode = os.O_RDONLY | os.O_WRONLY | os.O_RDWR
        if (flags & accmode) != os.O_RDONLY:
            return -errno.EACCES

    def read(self, path, size, offset):
        if len(path) > 0 and path[0] == '/':
            path = path[1:]
        fp = os.path.join(self.bkupdir, path)
        if not os.path.exists(fp):
            return -errno.ENOENT
        slen = os.path.getsize(fp)
        size = min(size, max(0, slen - offset))
        with open(fp, 'rb') as file:
            file.seek(offset)
            buf = file.read(size)
        return buf

def main():
    print("usage: fusestor.py <lnbkup> <mountpoint>")
    server = BkupFS(
        version="%prog " + fuse.__version__,
        dash_s_do='setsingle')

    server.setbkupdir(sys.argv[1])
    server.parse(errex=1)
    server.main()

if __name__ == '__main__':
    main()
