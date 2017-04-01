from __future__ import division
import argparse
import random
import itertools
from time import sleep
import subprocess
import os

def get_gamma(probe_rate):
    shape = 4
    desired_mean = 1/probe_rate
    desired_scale = shape/desired_mean
    return random.gammavariate(shape,1/desired_scale)

def get_exponential(probe_rate):
    r = random.expovariate
    return r(probe_rate)

def runCommand(command):
    p = subprocess.Popen(command, shell=True)
    pid, status = os.waitpid(p.pid, 0)

def callLoader(val, args):
    cpuLoadNeeded = 0.0
    memLoadNeeded = 0.0
    if args.cpuNeeded > 0.0:
        cpuLoadNeeded = args.cpuCalib * val
    if args.memNeeded > 0.0:
        memLoadNeeded = args.memCalib * val

    if args.cpuNeeded > 0.0 or args.memNeeded > 0.0:
        command = "./wilee/wileE -C {0} -M {1} -n 1 -c {2} -m {3} --no_papi".format(args.cpuNeeded, args.memNeeded, cpuLoadNeeded, memLoadNeeded)
        runCommand(command)
    if args.netNeeded:
        bandwidthVal = val * args.netCalib
        command = "iperf3 -c {0} -u -b {1:.2f}M -t 1".format(args.host, bandwidthVal)
        runCommand(command)
    if args.diskNeeded:
        countVal = val * args.diskCalib
        command = "dd if=/dev/zero of=/tmp/testfile bs=512 count={0}".format(int(countVal))
        runCommand(command)

def main(args):
    print ("Entering warm-up phase for {0} seconds.".format(args.warmup))
    sleep(args.warmup)
    print ("Entering loop phase. Traffic generation: ontime={0}s and offtime={1}s.".format(args.ontime, args.offtime))
    while True:
        for _ in itertools.repeat(None, args.ontime):
            val = None
            if args.dist=="gamma":
                val = get_gamma(3)
                print (val)
            if args.dist=="exponential":
                val = get_exponential(3)
                print (val)
            callLoader(val, args)
            sleep(1)
        sleep(args.offtime)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Create artificial load')
    parser.add_argument('-f', '--function', dest='dist', \
                        help='Distribution to be used for on/off period. \
                        Supported distributions are gamma.')
    parser.add_argument('-s', '--ontime', dest='ontime', type=int, \
                        help='On time in seconds.')
    parser.add_argument('-e', '--offtime', dest='offtime', type=int, \
                        help='Off time in seconds.')
    parser.add_argument('-w', '--warmup', dest='warmup', type=int, \
                        help='Specifies warmup period is seconds.')
    parser.add_argument('-c', '--cpu_calib', dest='cpuCalib', type=int, \
                        help='#Loops to achieve 100% CPU utilization.')
    parser.add_argument('-m', '--mem_calib', dest='memCalib', type=int, \
                        help='#Loops to achieve 100% Memory utilization.')
    parser.add_argument('-C', '--cpuNeeded', dest='cpuNeeded', type=float, \
                        help='Fraction of CPU utilization needed.')
    parser.add_argument('-M', '--memNeeded', dest='memNeeded', type=float, \
                        help='Fraction of Memory utilization needed.')
    parser.add_argument('-N', '--netNeeded', dest='netNeeded', action='store_true', \
                        help='Flag to set if network traffic is needed.')
    parser.add_argument('-n', '--net_calib', dest='netCalib', type=float, \
                        help='Specifies the max. bandwidth.')
    parser.add_argument('-D', '--diskNeeded', dest='diskNeeded', action='store_true', \
                        help='Flag to set if disk load is needed.')
    parser.add_argument('-d', '--disk_calib', dest='diskCalib', type=int, \
                        help='Count of blocks to write.')
    parser.add_argument('-i', '--iperfServer', dest='host', \
                        help='iPerf3 server address.')
    args = parser.parse_args()
    main(args)
