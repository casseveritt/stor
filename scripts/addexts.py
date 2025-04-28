#!/usr/bin/python

import os
import sys

if len(sys.argv) != 2:
    print("append extensions to unreferenced hash filenames for easier browsing")
    print("usage: addexts.py <bkupdir>")
    sys.exit(0)

bkupdir = sys.argv[1]

filecount = 0
for path, dirs, files in os.walk(os.path.join(bkupdir, "unreferenced")):
    for f in files:
        filecount += 1

for path, dirs, files in os.walk(os.path.join(bkupdir, "unreferenced")):
    for f in files:
        filecount -= 1
        fp = os.path.join(path, f)
        ext = os.popen(f'file --extension "{fp}"').read().split(': ')[1].split('/')[0]

        if ext[-1] == '\n':
            ext = ext[:-1]

        if len(ext) == 0 or ext == r'???':
            continue

        efp = os.path.join(os.path.dirname(fp), os.path.basename(fp) + "." + ext)
        print(f"{filecount} {os.path.basename(efp)}")
        os.rename(fp, efp)

