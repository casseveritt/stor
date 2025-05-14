#!/usr/bin/python

import os
import sys

def escape_bash_special_chars(text):
    t2 = re.sub(r"([\$\"])", r"\\\1", text)
    return t2

if len(sys.argv) != 2:
    print(f"usage: {sys.argv[0]} <bkupdir>")
    sys.exit(0)

bkupdir = sys.argv[1]
    
file_list = []

for path, dirs, files in os.walk(bkupdir):
    for f in files:
        fp = os.path.join(path, f)
        file_list.append([os.path.getsize(fp), fp])

file_list.sort()

count = len(file_list)
for f in file_list:
    count -= 1
    if count % 1000 == 0:
        print(count)
    b3sum = os.popen(f'b3sum "{f[1]}"').read().split(' ')[0]
    if b3sum != os.path.basename(f[1]):
        print(b3sum, os.path.basename(f[1])) 
