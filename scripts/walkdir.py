#!/usr/bin/python

import os
import sys
import shutil

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




def walkdir(srcdir, dstdir):

    to_copy = []

    for path, dirs, files in os.walk(srcdir):
        if path.startswith(srcdir):
            path = path[len(srcdir):]
            if len(path) > 1 and path[0] == '/':
                path = path[1:]
        else:
            continue
        for f in files:
            sfp = os.path.join(srcdir, path, f)
            dfp = os.path.join(dstdir, path, f)
            if not files_identical(sfp, dfp, check_contents=True):
                to_copy.append(os.path.join(path, f))

    count = 1
    num = len(to_copy)
    for fp in to_copy:
        s = os.path.join(srcdir, fp)
        d = os.path.join(dstdir, fp)
        if not os.path.exists(os.path.dirname(d)):
            os.makedirs(os.path.dirname(d))
            print(f"making {os.path.dirname(d)}")
        print(f"{num-count} {fp}")
        shutil.copy2(s, d)
        count += 1




if len(sys.argv) < 3:
    print("usage: walkdir <path>")

walkdir(sys.argv[1], sys.argv[2])

