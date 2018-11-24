import sys
import os
import re
import json
from math import isinf
from matplotlib import pyplot as plt
from statistics import median, mean, stdev

def _read_json(fname):
    with open(fname) as infile:
        return json.loads(infile.read())

def get_rtt_samples(xlist):
    lost = [ xd['usersend'] for ts,xd in xlist \
        if isinf(xd['wiresend']) or isinf(xd['wirerecv']) ]
    rtt = [ xd['wirerecv'] - xd['wiresend'] for ts,xd in xlist \
        if not isinf(xd['wirerecv']) and not isinf(xd['wiresend']) ]
    sendtimes = [ xd['usersend'] for ts,xd in xlist ]
    senddiffs = [ sendtimes[i] - sendtimes[i-1] for i in range(1,len(sendtimes)) ]
    start = min(sendtimes)
    end = max(sendtimes)
    return rtt,start,end

    #print("Lost: {}".format(len(lost)))
    #printstats('rtt', rtt)
    #printstats('senddiffs', senddiffs)

def print_info(i, fname):
    if 'freebsd' in fname:
        key = 'cpu7_idle'
    elif 'pib' in fname:
        key = 'cpu0_idle'
    elif 'pi3' in fname:
        key = 'cpu3_idle'
    d = _read_json(fname)
    cpumon = d['monitors']['cpu']
    idle = [ d[key] for _,d in cpumon ]

    for k in d['monitors'].keys():
        if k.startswith('rtt'):
            rttmon = d['monitors'][k]
            rttsamp,starttime,endtime = get_rtt_samples(rttmon['ping'])
            assert(rttmon['libpcap_stats']['pcapdrop'] == 0)
            psent = rttmon['probe_config']['total_probes_emitted']
            preceived = rttmon['probe_config']['total_probes_received']
            break

    #starttime = d['start']
    #endtime = d['end']
    pps = psent / (endtime-starttime)

    print("{:3d} {:.2f} {:.3f} {:.3f} {:4d} {:4d} {:1d} {:.6f} {:.6f}".format(i,pps,mean(idle),stdev(idle),psent,preceived,psent-preceived,mean(rttsamp),stdev(rttsamp)))

def analyze(infolder):
    '''
    Target pps
    Actual pps
    CPU idle mean
    CPU idle stdev
    Probes sent
    Probes received
    RTT mean
    RTT stdev
    '''
    for i in range(1, 201):
        xname = os.path.join(infolder, "send_ping{}.json".format(i))
        if os.path.exists(xname):
            print_info(i, xname)

def usage(pname):
    print("usage: {} <foldername>".format(pname))
    sys.exit(0)

def main(argv):
    if len(argv) != 2:
        usage(argv[0])
    if not os.path.isdir(argv[1]):
        print("{} is not a directory".format(argv[1]))
        usage(argv[0])
    analyze(argv[1])

if __name__ == '__main__':
    main(sys.argv)
