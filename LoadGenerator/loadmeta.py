from __future__ import division
import sys
import argparse
import random
import itertools
from time import sleep
import subprocess
import os
import signal

extproc = []
stop = False

def sighandler(*args):
    _cleanup()
    global stop
    stop = True
    print("\nStopping...")

def _cleanup():
    global extproc
    for p in extproc:
        p.kill()
        p.wait()
    # be really sure that any stray processes are dead.
    for c in ['wileE','iperf','dd']:
        p = subprocess.Popen("killall {}".format(c), shell=True, stderr=subprocess.DEVNULL)
        p.wait()
    extproc = []

def get_gamma(probe_rate):
    shape = 4
    desired_mean = 1/probe_rate
    desired_scale = shape/desired_mean
    return random.gammavariate(shape,1/desired_scale)

def get_exponential(probe_rate):
    r = random.expovariate
    return r(probe_rate)

def callLoader(val, args):
    cpuLoadNeeded = 0.0
    memLoadNeeded = 0.0
    if args.cpuNeeded > 0.0:
        cpuLoadNeeded = args.cpuCalib * val
    if args.memNeeded > 0.0:
        memLoadNeeded = args.memCalib * val

    command = None
    if args.cpuNeeded > 0.0 or args.memNeeded > 0.0:
        command = "./wilee/wileE -C {0} -M {1} -n 1 -c {2} -m {3} --no_papi".format(args.cpuNeeded, args.memNeeded, cpuLoadNeeded, memLoadNeeded)
    if args.netNeeded:
        bandwidthVal = val * args.netCalib
        command = "iperf3 -c {0} -u -b {1:.2f}M -t 1".format(args.host, bandwidthVal)
    if args.diskNeeded:
        countVal = val * args.diskCalib
        command = "dd if=/dev/zero of={} bs=512 count={0}".format(int(countVal), args.outfile)

    _cleanup()
    global extproc
    extproc.append(subprocess.Popen(command, shell=True))
    if args.cpuNeeded or args.memNeeded:
        # n-1 more procs for cpu cores
        for i in range(1, args.cpuCores):
            extproc.append(subprocess.Popen(command, shell=True))

def main(args):
    if args.cpuNeeded or args.memNeeded:
        print("Starting {} processes".format(args.cpuCores))
    print ("Entering warm-up phase for {0} seconds (doing nothing).".format(args.warmup))
    sleep(args.warmup)
    print ("Entering loop phase with ontime={}s and offtime={}s.".format(args.ontime, args.offtime))

    distfn = get_exponential
    if args.dist == 'gamma':
        distfn = get_gamma

    while not stop:
        sys.stdout.flush()
        val = distfn(1/args.ontime)
        print("On for {:3.3f}s ... ".format(val), end='')
        sys.stdout.flush()
        callLoader(val, args) # start up process(es) to generate load
        sleep(val)            # active time
        _cleanup()            # kill any procs still running

        if stop:              # check if we've been asked to stop 
            break

        val = distfn(1/args.offtime)
        print ("off for {}s".format(val))
        sleep(val)            # quiescent time

        #for _ in itertools.repeat(None, args.ontime):
        #    val = None
        #    if args.dist=="gamma":
        #        val = get_gamma(1/3)
        #        #print (val)
        #    if args.dist=="exponential":
        #        val = get_exponential(1/args.ontime)
        #        #print (val)
        #    print("...{:3.3f}".format(val), end='')
        #    sys.stdout.flush()
        #    callLoader(val, args)
        #    sleep(1)
        #print ("Off.")
        #sleep(args.offtime)

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, sighandler)
    signal.signal(signal.SIGINT, sighandler)

    parser = argparse.ArgumentParser(description='Create artificial load')
    parser.add_argument('--function', dest='dist', 
                        default="exponential",
                        help='Distribution to be used for on/off period. '\
                        'Supported distributions are gamma and exponential.')
    parser.add_argument('-s', '--ontime', dest='ontime', type=int, 
                        default=1,
                        help='On time in seconds.')
    parser.add_argument('-e', '--offtime', dest='offtime', type=int,
                        default=1,
                        help='Off time in seconds.')
    parser.add_argument('-w', '--warmup', dest='warmup', type=int,
                        default=1,
                        help='Specifies warmup period is seconds.')
    parser.add_argument('-c', '--cpu_calib', dest='cpuCalib', type=int,
                        help='Loops to achieve full CPU utilization.')
    parser.add_argument('-m', '--mem_calib', dest='memCalib', type=int,
                        help='Loops to achieve full memory utilization')
    parser.add_argument('-C', '--cpuNeeded', dest='cpuNeeded', type=float, 
                        default=0.0,
                        help='Fraction of CPU utilization needed.')
    parser.add_argument('-x', '--cores', dest='cpuCores', type=int,
                        default=1, help='How many cores to assume for generating CPU load')
    parser.add_argument('-M', '--memNeeded', dest='memNeeded', type=float, 
                        default=0.0,
                        help='Fraction of Memory utilization needed.')
    parser.add_argument('-N', '--netNeeded', dest='netNeeded', 
                        action='store_true', default=False,
                        help='Flag to set if network traffic is needed.')
    parser.add_argument('-n', '--net_calib', dest='netCalib', type=float, 
                        help='Specifies the max. bandwidth.')
    parser.add_argument('-D', '--diskNeeded', dest='diskNeeded', 
                        action='store_true', default=False,
                        help='Flag to set if disk load is needed.')
    parser.add_argument('-d', '--disk_calib', dest='diskCalib', type=int, 
                        help='Count of blocks to write.')
    parser.add_argument('-f', '--outfile', dest='outfile', 
                        help='File to write to for disk load.')
    parser.add_argument('-i', '--iperfServer', dest='host', 
                        help='iPerf3 server address.')
    args = parser.parse_args()

    if not (args.cpuNeeded > 0.0 or args.memNeeded > 0.0 \
        or args.diskNeeded or args.netNeeded):
        print("Nothing to do.  Must specify cpu/mem/disk/net activity.")
        parser.print_usage()
    elif args.cpuNeeded > 0 and args.cpuCalib is None:
        print("You asked for CPU load, but cpu calibration needs to be given")
    elif args.memNeeded > 0 and args.memCalib is None:
        print("You asked for memory load, but mem calibration needs to be given")
    elif args.diskNeeded and (args.diskCalib is None or args.outfile is None):
        print("You asked for disk load, but you need to specify #blocks and location to write")
    elif args.netNeeded and (args.netCalib is None or args.host is None):
        print("You asked for net load, but you need to specify bw and target host")
    else:
        main(args)
