from __future__ import division
import argparse
import random
import itertools
from time import sleep

def get_gamma(probe_rate):
    shape = 4
    desired_mean = 1/probe_rate
    desired_scale = shape/desired_mean
    return random.gammavariate(shape,1/desired_scale)

def callLoader(val):
    # TODO fix logic for generating load
    print (val)

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
            callLoader(val)
            sleep(1)
        sleep(args.offtime)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Create artificial load')
    parser.add_argument('-d', '--distribution', dest='dist', \
                        help='Distribution to be used for on/off period. \
                        Supported distributions are gamma.')
    parser.add_argument('-s', '--ontime', dest='ontime', type=int, \
                        help='On time in seconds')
    parser.add_argument('-e', '--offtime', dest='offtime', type=int, \
                        help='Off time in seconds')
    parser.add_argument('-w', '--warmup', dest='warmup', type=int, \
                        help='Specifies warmup period is seconds')
    args = parser.parse_args()
    main(args)
