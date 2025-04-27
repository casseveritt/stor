#!/usr/bin/python

import re
import os
import sys
import sqlite3

def escape_bash_special_chars(text):
    t2 = re.sub(r"([\$])", r"\\\1", text)
    return t2

def import2filestore(bkupdir, importdir):
    
    con = sqlite3.connect(os.path.join(bkupdir, "db"))


    if importdir[-1] != '/':
        importdir += '/'

    cur = con.cursor()
    cur.execute("create table if not exists b3sums (b3sum, relpath)")
    con.commit()
    rows = cur.execute("select b3sum, relpath from b3sums").fetchall()
    
    relpath2b3sum = {}
    b3sum2relpath = {}
    
    for row in rows:
        b3sum = row[0]
        relpath = row[1]
        if relpath in relpath2b3sum.keys():
            print(f"can't have duplicate relpaths {relpath}")
            continue
        relpath2b3sum[relpath] = b3sum
        
        if b3sum not in b3sum2relpath.keys():
            b3sum2relpath[b3sum] = []
            
        b3sum2relpath[b3sum].append(relpath)

    to_link = []
        
    for path, dirs, files in os.walk(importdir):
        relpath = path[len(importdir):]
        for f in files:
            rfp = os.path.join(relpath, f)
            if rfp in relpath2b3sum.keys():
                print(f"duplicate relpath can't be imported: {rfp}")
                continue
            to_link.append(rfp)

    count = len(to_link)            
    try:
        for rfp in to_link:
            count -= 1
            ifp = os.path.join(importdir, rfp)
            ifpe = escape_bash_special_chars(ifp)
            b3sum = os.popen(f'b3sum "{ifpe}"').read().split(' ')[0]
            
            fsfp = os.path.join(bkupdir, "files", b3sum[:2], b3sum)
            if not os.path.exists(fsfp):
                print(f"{count} link {fsfp} <-> {rfp}")
                os.link(ifp, fsfp)
            
            cur.execute("insert into b3sums (b3sum, relpath) values (?, ?)", (b3sum, relpath))
            os.unlink(ifp)

    except KeyboardInterrupt:
        print("caught keyboard interrupt, cleaning up...")

    finally:
        print("calling con.commit()")
        con.commit()

if len(sys.argv) != 3:
    print("usage: import2filestore.py <bkupdir> <importdir>")
    sys.exit(0)

bkupdir = sys.argv[1]
importdir = sys.argv[2]

import2filestore(bkupdir, importdir)

