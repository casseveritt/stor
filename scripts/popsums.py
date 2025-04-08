#!/usr/bin/python

import os
import sys
import shutil
import sqlite3

def files_identical(a, b, check_contents = False):
    if not os.path.exists(a) or not os.path.exists(b):
        return False

    a_sz = os.path.getsize(a)
    b_sz = os.path.getsize(b)

    if a_sz != b_sz:
        return False

    if not check_contents:
        return True

    a_b3 = os.popen(f'b3sum "{a}"').read().split(' ')[0]
    b_b3 = os.popen(f'b3sum "{b}"').read().split(' ')[0]

    return a_b3 == b_b3




def walkdir(bkupdir, cur):

    needs_sum = []

    res = cur.execute("select relpath from b3sums")
    sumpaths = set()
    for result in res.fetchall():
        sumpaths.add(result[0])


    walkedpaths = set()
    for path, dirs, files in os.walk(bkupdir):
        if path.startswith(bkupdir):
            path = path[len(bkupdir):]
            if len(path) > 1 and path[0] == '/':
                path = path[1:]
        else:
            continue
        for f in files:
            walkedpaths.add(os.path.join(path, f))

    needssum = walkedpaths - sumpaths

    print(f"need to compute sums for {len(needssum)} files")


if len(sys.argv) < 3:
    print("usage: popsums <db> <path>")
    sys.exit(0)


con = sqlite3.connect(sys.argv[1])
cur = con.cursor()

walkdir(sys.argv[2], cur)

