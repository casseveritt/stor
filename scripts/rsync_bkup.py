#!/usr/bin/python

import datetime
import os
import random
import sys
import time

if len(sys.argv) != 1:
    print(f"usage: {sys.argv[0]}")
    sys.exit(0)

time.sleep(random.randint(0, 1800))

cmd = r"rsync -hav -f '- /bkup/local/***' -e 'ssh -p 23434' starkville.hopto.org:/stor0/bkup /stor0"
result = os.popen(cmd).read()

local = r"/stor0/bkup/local/"
if not os.path.exists(local):
    os.makedirs(local)
log = open(os.path.join(local, "rsync.log"), "a")

now = datetime.datetime.now()
date_time_str = now.strftime(r"%Y-%m-%d %H:%M:%S")
log.write("=========================\n")
log.write(date_time_str + '\n')
log.write(cmd + '\n')
log.write("-------------------------\n")
log.write(result)

