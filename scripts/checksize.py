#!/usr/bin/python

import os
import sys
import sqlite3

if len(sys.argv) != 2:
    print(f"usage: {sys.argv[0]} <bkupdir>")
    sys.exit(0)

bkupdir = sys.argv[1]

con = sqlite3.connect(os.path.join(bkupdir, "db"))
cur = con.cursor()

rows = cur.execute("select distinct b3sum, size from b3sums where size > -1 order by b3sum").fetchall()

count = len(rows)
for r in rows:
    count -= 1
    b3sum = r[0]
    sz = r[1]
    fp = os.path.join(bkupdir, "files", b3sum[:2], b3sum)
    size = os.path.getsize(fp)    
    if sz != size:
        print(f"{count:9} {b3sum} db size: {sz:,} != actual size {size:,}")
