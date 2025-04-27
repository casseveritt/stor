#!/usr/bin/python

import re
import os
import sys
import shutil
import sqlite3

if len(sys.argv) != 4:
    print("usage: link2filestore <db> <filestore> <linkdir>")
    sys.exit(0)

db = sys.argv[1]
filestore = sys.argv[2]
linkdir = sys.argv[3]

con = sqlite3.connect(db)
cur = con.cursor()

files = cur.execute("select * from b3sums order by relpath").fetchall()

count = len(files)

for file in files:
    count -= 1
    relpath = file[1]
    b3sum = file[0]
    fp = os.path.join(linkdir, relpath)
    if not os.path.exists(fp):
        if not os.path.exists(os.path.dirname(fp)):
            print(f"{count} making {os.path.dirname(fp)}")
            os.makedirs(os.path.dirname(fp))
        fstorepath = os.path.join(filestore, b3sum[:2], b3sum)
        os.link(fstorepath, fp)
