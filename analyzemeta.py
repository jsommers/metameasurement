import json
import argparse
from statistics import mean, stdev, median
from math import isinf
from collections import defaultdict

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
    print("\nlibpcap info: recv: {recv}  pcapdrop: {pcapdrop}  " \
          "ifdrop: {ifdrop}\n".format(**xdict['libpcap_stats']))

def analyze_io(xli):
    # busy_time?
    if len(xli) == 0:
        return
    xd = xli[0][1]
    #print(xd.keys())

def analyze_cpu(xli):
    if len(xli) == 0:
        return
    keys_of_interest = []
    data = defaultdict(list)
    xd = xli[0][1]
    for key in xd.keys():
        if 'idle' in key:
            keys_of_interest.append(key)
    for ts,xd in xli:
        for k in keys_of_interest:
            data[k].append(xd[k])

    print("\nMean/stdev CPU idle:")
    for k in sorted(keys_of_interest):
        m = mean(data[k])
        s = stdev(data[k])
        print("\t{}: {:.3f} ({:.3f})".format(k, m, s))
        lowcpu = len([x for x in data[k] if x < 1])
        if lowcpu > 0:
            print("\t\t{} measurements had low (<1%) idle CPU".format(lowcpu))

def analyze_mem(xli):
    if len(xli) == 0:
        return
    available = [ xd['available'] for _,xd in xli ]
    print("\nMemory available (Bytes) mean (stdev): {:.0f} ({:.0f})".format(
        mean(available), stdev(available)))

def analyze_netcounters(xli):
    if len(xli) == 0:
        return
    keys_of_interest = []
    counters = defaultdict(list)

    xd = xli[0][1]
    for key in xd.keys():
        if 'drop' in key:
            keys_of_interest.append(key)
        elif 'err' in key:
            keys_of_interest.append(key)
    for ts,xd in xli:
        for k in keys_of_interest:
            counters[k].append(xd[k])

    print()
    flag = False
    for k in sorted(keys_of_interest):
        s = sum(counters[k])
        if s > 0:
            print("{}: count is non-zero ({})".format(k, s))
            flag = True
    if not flag:
        print("No drops or errors in netstat counters")

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
