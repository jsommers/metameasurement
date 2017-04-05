import json
import argparse
from statistics import mean, stdev, median
from math import isinf

def printstats(name, xlist):
    print("{}".format(name))
    print("\tmean: {}".format(mean(xlist)))
    if len(xlist) >= 2:
        print("\tstdev: {}".format(stdev(xlist)))
    print("\tmedian: {}".format(median(xlist)))

def analyze(key, xdict):
    print("Analyzing {} ({})".format(key, xdict['probe_config']))
    for rttkey in xdict.keys():
        if rttkey.startswith('ttl') or rttkey == 'ping':
            gatherandprint(rttkey, xdict[rttkey])

def gatherandprint(rkey, xlist):
    print("Results for {}".format(rkey))

    lost = [ xd['send'] for ts,xd in xlist if isinf(xd['recv']) ]
    rtt = [ xd['recv'] - xd['send'] for ts,xd in xlist if not isinf(xd['recv']) and not isinf(xd['send']) ]
    sendtimes = [ xd['send'] for ts,xd in xlist if not isinf(xd['send']) ]
    senddiffs = [ sendtimes[i] - sendtimes[i-1] for i in range(1,len(sendtimes)) ]
    print("Lost: {}".format(len(lost)))
    printstats('rtt', rtt)
    printstats('senddiffs', senddiffs)

def main():
    parser = argparse.ArgumentParser(
            description='Analyze RTTs...')
    parser.add_argument('jsonmeta', nargs=1)
    args = parser.parse_args()

    infile = args.jsonmeta[0]
    with open(infile) as infileh:
        meta = json.load(infileh)

    for key in meta['monitors'].keys():
        if key.startswith('rtt'):
            analyze(key, meta['monitors'][key])

if __name__ == '__main__':
    main()
