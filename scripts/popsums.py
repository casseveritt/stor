#!/usr/bin/python

import re
import os
import sys
import shutil
import sqlite3

def escape_bash_special_chars(text):
    t2 = re.sub(r"([\$])", r"\\\1", text)
    return t2

def files_identical(a, b, check_contents = False):
    if not os.path.exists(a) or not os.path.exists(b):
        return False

    a_sz = os.path.getsize(a)
    b_sz = os.path.getsize(b)

    if a_sz != b_sz:
        return False

    if not check_contents:
        return True

    ae = escape_bash_special_chars(a)
    be = escape_bash_special_chars(b)

    a_b3 = os.popen(f'b3sum "{ae}"').read().split(' ')[0]
    b_b3 = os.popen(f'b3sum "{be}"').read().split(' ')[0]

    return a_b3 == b_b3


def walkdir(bkupdir, con):

    needs_sum = []

    cur = con.cursor()
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

    count = len(needssum)
    for n in needssum:
        print(count, n)
        count -= 1
        p = os.path.join(bkupdir, n)
        pe = escape_bash_special_chars(p)
        b3sum = os.popen(f'b3sum "{pe}"').read().split(' ')[0]
        if len(b3sum) > 60:
            cur.execute("insert into b3sums values (?, ?)", (b3sum, n,))
            print(b3sum)
            con.commit()




if len(sys.argv) < 3:
    print("usage: popsums <db> <path>")
    sys.exit(0)


con = sqlite3.connect(sys.argv[1])

walkdir(sys.argv[2], con)

