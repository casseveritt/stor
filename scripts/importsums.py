#!/usr/bin/python

import re
import sys
import sqlite3

def escape_bash_special_chars(text):
    t2 = re.sub(r"([\$])", r"\\\1", text)
    return t2

def list_from_file(filename):
    with open(filename, 'r') as file:
        lines = file.readlines()
        return lines

def importsums(dbfile, importfile, leadingpath):
    if leadingpath[-1] != '/':
        leadingpath += '/'

    con = sqlite3.connect(dbfile)
    cur = con.cursor()
    cur.execute("create table if not exists b3sums (b3sum, relpath)")
    con.commit()
    res = cur.execute("select relpath from b3sums")
    sumpaths = set()
    for result in res.fetchall():
        sumpaths.add(result[0])

    with open(importfile, 'r') as file:
        lines = file.readlines()    

    pat = re.compile(r"^([0-9a-f]+)\s+(.+)$")

    linecount = len(lines)
    count = 0

    for line in lines:
        count += 1
        match = pat.search(line)
        if not match:
            print(f"failed to match line: {line}")
            raise Exception(f"failed to match line: {line}")
            continue
        b3sum = match.group(1)
        relpath = match.group(2)
        if relpath[:len(leadingpath)] == leadingpath:
            relpath = relpath[len(leadingpath):]
        if relpath in sumpaths:
            print(f"skipping existing record for {relpath}")
            continue
        print(f"{linecount - count} -- {b3sum} -- {relpath}")
           
        cur.execute("insert into b3sums values (?, ?)", (b3sum, relpath,))

    con.commit()

if len(sys.argv) != 4:
    print("usage: importsums <dbfile> <importfile> <leadingpath>")
    sys.exit(0)


importsums(sys.argv[1], sys.argv[2], sys.argv[3])

