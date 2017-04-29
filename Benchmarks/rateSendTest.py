#!/usr/bin/env python3

import sys
from subprocess import run
import os

ptype="type=ping"
xname='ping'

if sys.platform == 'linux':
    cmdprefix = ""
    dest="10.43.43.3"
    interface="eth0"
    cpu = max(os.sched_getaffinity(os.getpid()))
    cpupin = "-C{}".format(cpu)
else: # freebsd
    cmdprefix = "cpuset -c -l7 "
    cpupin = ""
    dest="10.13.13.1"
    interface="bce1"

for rate in range(1,501,4):
    cmd = '{}python3 metameasurement.py {}-l -Mcpu -Mrtt:interface={}:
{}:dest={}:rate={} -F send_{}{} -c "sleep 60"'.format(cmdprefix, cpupin, interface, ptype, dest, ra
te, xname, rate)
    print("Running {}".format(rate))
    print(cmd)
    proc = run(cmd, shell=True)
    assert(proc.returncode == 0)

