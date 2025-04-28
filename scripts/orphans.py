#!/usr/bin/python

import os
import sys
import sqlite3

if len(sys.argv) != 2:
    print("usage: orphans.py <bkupdir>")
    sys.exit(0)

bkupdir = sys.argv[1]

con = sqlite3.connect(os.path.join(bkupdir, "db"))
cur = con.cursor()

rows = cur.execute("select b3sum, relpath from b3sums order by relpath").fetchall()

count = len(rows)

relpath2b3sum = {}
b3sum2relpath = {}
    
for row in rows:
    b3sum = row[0]
    relpath = row[1]
    if relpath in relpath2b3sum.keys():
        print(f"can't have duplicate relpaths {relpath}")
        continue
    relpath2b3sum[relpath] = b3sum
    
    if b3sum not in b3sum2relpath.keys():
        b3sum2relpath[b3sum] = []
        
    b3sum2relpath[b3sum].append(relpath)

for row in rows:
    count -= 1
    relpath = row[1]
    b3sum = row[0]
    fsp = os.path.join(bkupdir, "files", b3sum[:2], b3sum)
    if not os.path.exists(fsp):
        print(f"dangling row: {relpath}")

filecount = 0
unreferenced = 0
rowcount = 0
for path, dirs, files in os.walk(os.path.join(bkupdir, "files")):
    for f in files:
        filecount += 1
        if f not in b3sum2relpath.keys():
            unreferenced += 1
            unrefp = os.path.join(bkupdir, "unreferenced", f[:2], f)
            if not os.path.exists(unrefp):
                if not os.path.exists(os.path.dirname(unrefp)):
                    print(f"making {os.path.dirname(unrefp)}")
                    os.makedirs(os.path.dirname(unrefp))
                fstorepath = os.path.join(bkupdir, "files", f[:2], f)
                os.rename(fstorepath, unrefp)
        else:
            rowcount += len(b3sum2relpath[f])

print(f"{unreferenced} unreferenced files of {filecount}")
print(f"{rowcount} rows accounted for of {len(rows)}")