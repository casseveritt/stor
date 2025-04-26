#!/usr/bin/python

import sys
import os
import sqlite3

def fetchall_sums(dbfile):
    db = sqlite3.connect(dbfile)
    cur = db.cursor()
    res = cur.execute("select b3sum, relpath from b3sums")
    return res.fetchall()

if len(sys.argv) != 3:
    print(f"usage: compare-dbs.py <adb> <bdb>")
    sys.exit(0)

alist = fetchall_sums(sys.argv[1])
blist = fetchall_sums(sys.argv[2])

aset = set([el[0] for el in alist])
bset = set([el[0] for el in blist])

anotb = (aset - bset)

fetchlist = []

for asum in anotb:
    relpath = [a[1] for a in alist if a[0] == asum][0]
    bsuml = [b[0] for b in blist if b[1] == relpath]
    if len(bsuml) == 0:
        print(f"in a, but not b: {relpath}, asum={asum}")
        continue
    bsum = bsuml[0]

    fetchlist.append({"relpath": relpath, "asum": asum, "bsum": bsum})

    db = sqlite3.connect(sys.argv[1])
    cur = db.cursor()

    for f in fetchlist:
        relpath = f["relpath"]
        asum = f["asum"]
        bsum = f["bsum"]
        print(f"setting {relpath} sum to {bsum}")
        res = cur.execute("update b3sums set b3sum = ? where relpath = ?", (bsum, relpath))

    db.commit()

"""
for f in fetchlist:
    relpath = f["relpath"]
    asum = f["asum"]
    bsum = f["bsum"]
    os.system(f"ls -l 'bkup/{relpath}'")

for f in fetchlist:
    relpath = f["relpath"]
    asum = f["asum"]
    bsum = f["bsum"]
    cmd = f"scp strkpi.local:/media/cass/stor/bkup/.filestore/{bsum[:2]}/{bsum} 'bkup/{relpath}'"
    print(cmd)
    os.system(cmd)
    os.system(f"b3sum 'bkup/{relpath}'")

"""

