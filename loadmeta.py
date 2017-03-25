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

def callLoader(val, args):
    cpuLoadNeeded = 0.0
    memLoadNeeded = 0.0
    if args.cpuNeeded > 0.0:
        cpuLoadNeeded = args.cpuCalib * val
    if args.memNeeded > 0.0:
        memLoadNeeded = args.memCalib * val

    # TODO configure the tool properly
    # TODO add network load logic
    command = "./wilee/wileE -C {0} -M {1} -n 1 -c {2} -m {3} --no_papi".format(args.cpuNeeded, args.memNeeded, cpuLoadNeeded, memLoadNeeded)
    print (command)
    p = subprocess.Popen(command, shell=True)
    pid, status = os.waitpid(p.pid, 0)

def main(args):
    print ("Entering warm-up phase for {0} seconds.".format(args.warmup))
    sleep(args.warmup)
    print ("Entering loop phase. Traffic generation: ontime={0}s and offtime={1}s.".format(args.ontime, args.offtime))
    while True:
        for _ in itertools.repeat(None, args.ontime):
            val = None
            # TODO add switch for other distributions
            if args.dist=="gamma":
                val = get_gamma(2)
            callLoader(val, args)
            sleep(1)
        sleep(args.offtime)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Create artificial load')
    parser.add_argument('-d', '--distribution', dest='dist', \
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
    args = parser.parse_args()
    main(args)
