#!/usr/bin/python

import os
import sys

def walkdir(dirname):
    for path, dirs, files in os.walk(dirname):
        print(f"{path}")


if len(sys.argv) < 2:
    print("usage: walkdir <path>")

walkdir(sys.argv[1])

