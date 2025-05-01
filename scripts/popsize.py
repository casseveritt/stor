#!/usr/bin/python

import os
import sys
import sqlite3

if len(sys.argv) != 2:
    print("usage: popsize.py <bkupdir>")
    sys.exit(0)

bkupdir = sys.argv[1]

con = sqlite3.connect(os.path.join(bkupdir, "db"))
cur = con.cursor()

rows = cur.execute("select b3sum, relpath from b3sums where size = -1 order by b3sum").fetchall()

sumset = set()
for r in rows:
    sumset.add(r[0])

try:
    count = len(sumset)
    sumset = set()
    for r in rows:
        b3sum = r[0]
        if b3sum in sumset:
            continue
        sumset.add(b3sum)
        count -= 1
        relpath = r[1]
        fp = os.path.join(bkupdir, "files", b3sum[:2], b3sum)
        size = os.path.getsize(fp)    
        cur.execute("update b3sums set size = ? where b3sum = ?", (size, b3sum))
        print(f"{count:9} {b3sum} {size:,}")
        #print(f"update b3sums set size = {size} where b3sum = '{b3sum}';")
except KeyboardInterrupt:
    print("caught keyboard interrupt")
finally:
    print("committing transaction")
    con.commit()
    
con.commit()