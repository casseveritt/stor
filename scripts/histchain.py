#!/usr/bin/python

import re
import os
import subprocess
import sys
import sqlite3

def hash_list(list):
    p = subprocess.Popen(['b3sum'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    for l in list:
        p.stdin.write(l + "\n")
    p.stdin.close()
    hash = p.stdout.read().split(' ')[0]
    return hash


def parse_hist(hist):
    l = []
    count = 0
    lasthash = 0
    for h in hist:
        if h == "":
            continue
        count += 1
        if re.match(r"\+ [0-9a-f]{64}", h):
            l.append(h[2:66])            
        elif re.match(r"- [0-9a-f]{64}", h):
            l.remove(h[2:66])
        elif re.match(r"= [0-9a-f]{64}", h):
            lasthash = count
            if h[2:66] != hash_list(l):
                print(f"validation failure at line {count}")
                sys.exit(1)
        else:
            print(f"parse error at line {count}")
            print(h)
            sys.exit(1)
    if lasthash != count:
        print("last line must be an = (hash) line")
    l.sort()
    return l

def gen_file_list(bkupdir):
    file_list = []
    for path, dirs, files in os.walk(os.path.join(bkupdir, "files")):
        dirs.sort()
        files.sort()
        for f in files:
            file_list.append(f)
    return file_list

if len(sys.argv) != 3:
    print(f"usage: {sys.argv[0]} <bkupdir> <manifesthist>")
    sys.exit(0)

bkupdir = sys.argv[1]
manifesthist = sys.argv[2]

if os.path.exists(manifesthist):
    hist = open(manifesthist, "r").read().split('\n')
else:
    hist = []

file_list = gen_file_list(bkupdir)
hash = hash_list(file_list)
hist_list = parse_hist(hist)

hs = set()
for h in hist_list:
    hs.add(h)

fs = set()
for f in file_list:
    fs.add(f)

diff = []
for add in (fs - hs):
    diff.append(f"+ {add}")
for sub in (hs - fs):
    diff.append(f"- {sub}")

diff.sort(key = lambda x: x[2:66])

if len(diff) > 0:
    hf = open(manifesthist, "a")
    for d in diff:
        hf.write(d + '\n')
    hf.write(f"= {hash}\n")
    hf.close()
else:
    print("manifest not changed")

