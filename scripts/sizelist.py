#!/usr/bin/python

import os
import sys

if len(sys.argv) != 2:
    print("usage: sizelist.py <bkupdir>")
    sys.exit(0)

bkupdir = sys.argv[1]
    
file_list = []

count = 0
for path, dirs, files in os.walk(bkupdir):
    for f in files:
        count += 1
        fp = os.path.join(path, f)
        file_list.append([os.path.getsize(fp), fp])

file_list.sort()

count = len(file_list)
total = 0
for f in file_list:
    count -= 1
    print(f) 
    total += f[0]

print()
print(f"files: {len(file_list)}, bytes: {total}")
