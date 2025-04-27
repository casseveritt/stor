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


def mv2filestore(bkupdir, con):

    filestore = os.path.join(bkupdir, "files")

    os.makedirs(filestore, exist_ok=True)


    cur = con.cursor()
    res = cur.execute("select relpath, b3sum from b3sums")
    for relpath, b3sum in res.fetchall():
        relfilepath = os.path.join(bkupdir, relpath)
        prefix = b3sum[:2]
        filedir = os.path.join(filestore, prefix)
        os.makedirs(filedir, exist_ok=True)
        wrongfilepath = os.path.join(filestore, b3sum)
        filepath = os.path.join(filedir, b3sum)
        if os.path.exists(wrongfilepath) and not os.path.exists(filepath):
            print(f"fixing {relpath}")
            shutil.move(wrongfilepath, filepath)
            continue
        if not os.path.exists(relfilepath):
            continue
        if os.path.exists(filepath):
            print(f"filestore file {b3sum} already exists")
            os.remove(relfilepath)
            continue
        shutil.move(relfilepath, filepath)
        print(".", end='')





if len(sys.argv) < 3:
    print("usage: mv2filestore.py <db> <path>")
    sys.exit(0)


con = sqlite3.connect(sys.argv[1])

mv2filestore(sys.argv[2], con)

