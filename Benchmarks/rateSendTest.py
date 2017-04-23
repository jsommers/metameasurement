#!/usr/bin/env python3

import sys
from subprocess import run

ptype="type=ping"
dest="10.13.13.1"
interface='bce1'
xname='ping'

for rate in range(1,501,2):
    cmd = 'cpuset -c -l7 python3 metameasurement.py -l -Mcpu -Mrtt:interface={}:
{}:dest={}:rate={} -F send_{}{} -c "sleep 60"'.format(interface, ptype, dest, ra
te, xname, rate)
    print("Running {}".format(rate))
    print(cmd)
    proc = run(cmd, shell=True)
    assert(proc.returncode == 0)

