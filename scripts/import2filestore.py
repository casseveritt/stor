#!/usr/bin/python

import re
import os
import sys
import sqlite3

def escape_bash_special_chars(text):
    t2 = re.sub(r"([\$\"])", r"\\\1", text)
    return t2

def import2filestore(bkupdir, importdir, relpathprefix):
    
    if not os.path.exists(bkupdir):
        os.makedirs(bkupdir)
    
    con = sqlite3.connect(os.path.join(bkupdir, "db"))

    if importdir[-1] != '/':
        importdir += '/'
        
    if len(relpathprefix) > 0 and relpathprefix[-1] != '/':
        relpathprefix += '/'

    cur = con.cursor()
    cur.execute("create table if not exists relpaths (b3sum, relpath, size INTEGER DEFAULT -1, created DATETIME DEFAULT CURRENT_TIMESTAMP)")
    con.commit()
    rows = cur.execute("select b3sum, relpath from relpaths").fetchall()
    
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
            rfp = os.path.join(relpathprefix, relpath, f)
            if rfp in relpath2b3sum.keys():
                print(f"duplicate relpath can't be imported: {rfp}")
                continue
            to_link.append(os.path.join(relpath, f))

    count = len(to_link)            
    try:
        for prfp in to_link:
            count -= 1
            rfp = os.path.join(relpathprefix, prfp)
            ifp = os.path.join(importdir, prfp)
            ifpe = escape_bash_special_chars(ifp)
            b3sum = os.popen(f'b3sum "{ifpe}"').read().split(' ')[0]
            
            fsfp = os.path.join(bkupdir, "files", b3sum[:2], b3sum)
            if not os.path.exists(fsfp):
                if not os.path.exists(os.path.dirname(fsfp)):
                    print(f"{count} making {os.path.dirname(fsfp)}")
                    os.makedirs(os.path.dirname(fsfp))
                print(f"{count} link {fsfp} <-> {rfp}")
                os.link(ifp, fsfp)
            size = os.path.getsize(fsfp)            
            cur.execute("insert into relpaths (b3sum, relpath, size) values (?, ?, ?)", (b3sum, rfp, size))

    except KeyboardInterrupt:
        print("caught keyboard interrupt, cleaning up...")

    finally:
        print("calling con.commit()")
        con.commit()

if len(sys.argv) < 3 or len(sys.argv) > 4:
    print("usage: import2filestore.py <bkupdir> <importdir> [relpathprefix]")
    sys.exit(0)

bkupdir = sys.argv[1]
importdir = sys.argv[2]

if len(importdir) == 0 or importdir[0] == '/':
    print("importdir must be a relative path")
    sys.exit(1)
    
if importdir[-1] == '/':
    importdir = importdir[:-1]

if len(sys.argv) == 3:
    relpathprefix = os.path.basename(os.path.join(".", importdir))
else:
    relpathprefix = sys.argv[3]
    
import2filestore(bkupdir, importdir, relpathprefix)

