import json
import argparse
from statistics import mean, stdev, median
from math import isinf

def printstats(name, xlist):
    print("{}".format(name))
    if len(xlist) >= 1:
        print("\tmean: {}".format(mean(xlist)))
    if len(xlist) >= 2:
        print("\tstdev: {}".format(stdev(xlist)))
    if len(xlist) >= 1:
        print("\tmedian: {}".format(median(xlist)))

def analyze_rtt(key, xdict):
    print("Analyzing {} ({})".format(key, xdict['probe_config']))
    for rttkey in xdict.keys():
        if rttkey.startswith('ttl') or rttkey == 'ping':
            gatherandprint(rttkey, xdict[rttkey])

def analyze_cpu(xli):
    pass

def analyze_mem(xli):
    pass

def analyze_netcounters(xli):
    pass

def gatherandprint(rkey, xlist):
    print("Results for {}".format(rkey))
    lost = [ xd['usersend'] for ts,xd in xlist \
        if isinf(xd['wiresend']) or isinf(xd['wirerecv']) ]
    rtt = [ xd['wirerecv'] - xd['wiresend'] for ts,xd in xlist \
        if not isinf(xd['wirerecv']) and not isinf(xd['wiresend']) ]
    sendtimes = [ xd['usersend'] for ts,xd in xlist ]
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
            analyze_rtt(key, meta['monitors'][key])
    if 'cpu' in meta['monitors']:
        analyze_cpu(meta['monitors']['cpu'])
    if 'mem' in meta['monitors']:
        analyze_mem(meta['monitors']['mem'])
    if 'netstat' in meta['monitors']:
        analyze_netcounters(meta['monitors']['netstat'])
    if 'io' in meta['monitors']:
        analyze_io(meta['monitors']['io'])

if __name__ == '__main__':
    main()
