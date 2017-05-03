from __future__ import division
import sys
import argparse
import random
import itertools
from time import sleep, time, strftime
import subprocess
import multiprocessing
import os
import signal

extproc = []
stop = False
netcommand_base = ''

def sighandler(*args):
    _cleanup(False, None)
    global stop
    stop = True
    print("\nStopping...")

def _cleanup(net, netcmd):
    global extproc
    for p in extproc:
        try:
            p.terminate()
        except:
            pass
        try:
            p.wait()
        except:
            pass

        try:
            p.join()
        except:
            pass
    # be really sure that any stray processes are dead.
    for c in ['wileE','iperf','dd']:
        p = subprocess.Popen("killall {}".format(c), shell=True, stderr=subprocess.DEVNULL)
        p.wait()
    try:
        os.unlink(args.outfile)
    except:
        pass

    if net and netcmd:
        p = subprocess.Popen("{} stop".format(netcmd), shell=True, stderr=subprocess.DEVNULL)
        p.wait()

    extproc = []

def get_gamma(rate):
    mean = 1/rate
    shape = 4
    desired_mean = 1/mean
    desired_scale = shape/desired_mean
    return random.gammavariate(shape,1/desired_scale)

def get_exponential(rate):
    mean = 1/rate
    return random.expovariate(mean)

def get_const(mean):
    return mean

def _do_dd(cmd, tval):
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    # keep calling dd until we get killed.  sad!
    start = now = time()
    while now-start < tval:
        subprocess.call(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        now = time()
    sys.exit(0)

def callLoader(val, args):
    global netcommand_base
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
        netcommand_base = "ssh root@192.168.100.254 /root/toc1.sh"
        rate = 1000
        # command = "{} iperf3 -c {} -u -b {} -t {}".format(args.iperfremote, args.host, args.netbw, args.ontime)
        # command = "ssh root@10.42.42.3 /root/topifi.sh 30 {}".format(args.ontime)
        # command = "ssh root@192.168.100.254 /root/topifi.sh 500 {}".format(args.ontime)
        command = "{} {} {}".format(netcommand_base, rate, args.ontime)
    if args.diskNeeded:
        countVal = val * args.diskCalib
        command = "dd if=/dev/zero of={} bs=1024 count={}".format(args.outfile, int(countVal))

    _cleanup(args.netNeeded, netcommand_base)

    global extproc
    if args.cpuNeeded or args.memNeeded or args.netNeeded:
        extproc.append(subprocess.Popen(command, shell=True))
        # n-1 more procs for cpu cores
        if not args.netNeeded:
            for i in range(1, args.cpuCores):
                extproc.append(subprocess.Popen(command, shell=True))
    elif args.diskNeeded:
        p = multiprocessing.Process(target=_do_dd, args=(command,val))
        extproc.append(p)
        p.start()

def main(args):
    if args.cpuNeeded or args.memNeeded:
        print("Starting {} processes".format(args.cpuCores))
    print ("Entering warm-up phase for {0} seconds (doing nothing).".format(args.warmup))
    sleep(args.warmup)
    print ("Entering loop phase with ontime={}s and offtime={}s.".format(args.ontime, args.offtime))

    distfn = get_exponential
    if args.dist == 'gamma':
        distfn = get_gamma
    elif args.dist == 'constant':
        distfn = get_const

    start = time()
    val = distfn(args.offtime)
    print ("{} off for {}s".format(strftime("%Y%m%d%H%M%S"), val))
    sleep(val)            # quiescent time
    while not stop :
        sys.stdout.flush()
        val = distfn(args.ontime)
        sys.stdout.flush()
        callLoader(val, args) # start up process(es) to generate load
        print("{} on for {:3.3f}s ... ".format(strftime("%Y%m%d%H%M%S"), val))
        sleep(val)            # active time
        _cleanup(args.netNeeded, netcommand_base) # kill any procs still running

        if stop:              # check if we've been asked to stop 
            break

        val = distfn(args.offtime)
        print ("{} off for {}s".format(strftime("%Y%m%d%H%M%S"), val))
        sleep(val)            # quiescent time

        if args.runtime > 0:
            now = time()
            if now - start >= args.runtime:
                break

    print ("{} off and done".format(strftime("%Y%m%d%H%M%S")))


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, sighandler)
    signal.signal(signal.SIGINT, sighandler)

    parser = argparse.ArgumentParser(description='Create artificial load')
    parser.add_argument('-F', '--function', dest='dist', 
                        default="constant",
                        help='Distribution to be used for on/off period. '\
                        'Supported distributions are constant, gamma, exponential.')
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
    parser.add_argument('-n', '--net_calib', dest='netbw', type=str, 
                        help='Specifies the max. bandwidth (can use iperf bw-stye args).')
    parser.add_argument('-D', '--diskNeeded', dest='diskNeeded', 
                        action='store_true', default=False,
                        help='Flag to set if disk load is needed.')
    parser.add_argument('-d', '--disk_calib', dest='diskCalib', type=int, 
                        default=1000,
                        help='Count of blocks to write.')
    parser.add_argument('-f', '--outfile', dest='outfile', 
                        help='File to write to for disk load.')
    parser.add_argument('-i', '--iperfServer', dest='host', 
                        help='iPerf3 server address.')
    parser.add_argument('-I', '--iperfRemote', dest='iperfremote',
                        default='',
                        help='Command prefix for starting iperf (e.g., ssh)')
    parser.add_argument('-t', '--runtime', dest='runtime', 
                        default=0, type=int,
      help='Amount of time to run (default: keep running until interrupted).')
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
    elif args.netNeeded and (args.netbw is None or args.host is None):
        print("You asked for net load, but you need to specify bw and target host")
    else:
        main(args)
