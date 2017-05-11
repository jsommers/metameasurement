import sys
import os
import glob
import json
import re
from math import isinf
from matplotlib import pyplot as plt

def mkcdf(values):
    # precondition: values must be sorted!
    ticks = 100
    idxli = [ float(x)/ticks for x in range(0,ticks) ]
    xvals = []
    nval = len(values)
    for idx in idxli:
        pos = int(idx * nval)
        xvals.append(values[pos])
    idxli.append(1.0)
    xvals.append(values[-1])
    return xvals,idxli

def _read_json(fname):
    with open(fname) as infile:
        return json.loads(infile.read())

def get_cpu_cdf(directory, osname, pat):
    keydict = {
        'pib':'cpu0_idle',
        'pi3':'cpu3_idle',
        'linux':'cpu7_idle',
        'freebsd':'cpu7_idle',
    }
    files = glob.glob(os.path.join(directory,pat))
    assert(len(files) == 1)
    xd = _read_json(files[0])
    cpumon = xd['monitors']['cpu']
    key = keydict[osname]
    idlesamp = [ d[key] for t,d in cpumon ]
    return mkcdf(sorted(idlesamp))

def get_rtt_samples(xlist):
    lost = [ xd['usersend'] for ts,xd in xlist \
        if isinf(xd['wiresend']) or isinf(xd['wirerecv']) ]
    rtt = [ xd['wirerecv'] - xd['wiresend'] for ts,xd in xlist \
        if not isinf(xd['wirerecv']) and not isinf(xd['wiresend']) ]
    rtt = [ r*1000 for r in rtt ] # convert to milliseconds
    sendtimes = [ xd['usersend'] for ts,xd in xlist ]
    senddiffs = [ sendtimes[i] - sendtimes[i-1] for i in range(1,len(sendtimes)) ]
    return sorted(rtt)

def get_rtt_cdf(directory, osname, pat, ttl=1):
    files = glob.glob(os.path.join(directory,pat))
    assert(len(files) == 1)
    xd = _read_json(files[0])
    for k in xd['monitors'].keys():
        if k.startswith('rtt'):
            rttmon = xd['monitors'][k]
            break
    if 'ping' in files[0]:
        return mkcdf(get_rtt_samples(rttmon['ping']))
    else:
        return mkcdf(get_rtt_samples(rttmon['ttl_{}'.format(ttl)]))

def plot_cdfs(directory, osname):
    cpu = (
      ('baseline_900_cpu.json','CPU only (1s)'),
      ('baseline_900_cpu_interval5.json','CPU only (5s)'),
      ('baseline_900_allping.json','All monitors (ping, 1s)'),
      ('baseline_900_allping_interval5.json','All monitors (ping, 5s)'),
      ('baseline_900_allhoplimited.json','All monitors (hop-limited, 1s)'),
      ('baseline_900_allhoplimited_interval5.json','All monitors (hop-limited, 5s)'),
    )

    rtt = (
      ('baseline_900_rtt_interface*_typeping_*.json','RTT only (ping, 1s)'),
      ('baseline_900_rtt_interface*_typehoplimited_maxttl1*.json','RTT only (hop-limited, 1s)'),
      ('baseline_900_allping.json','All monitors (ping, 1s)'),
      ('baseline_900_allhoplimited.json','All monitors (hop-limited, 1s)'),
    )

    hoplimits = (
      ('baseline_900_allhoplimited.json','Hop-limited, maxttl=1, hop={}'),
      ('baseline_900_allhoplimited_2hops.json','Hop-limited, maxttl=2, hop={}'),
      ('baseline_900_allhoplimited_3hops.json','Hop-limited, maxttl=3, hop={}'),
      ('baseline_900_allhoplimited_4hops.json','Hop-limited, maxttl=4, hop={}'),
      ('baseline_900_allhoplimited_5hops.json','Hop-limited, maxttl=5, hop={}'),
    )

    plt.figure(figsize=(6,4))
    plt.subplot(111)
    i = 0 
    for pat,label in cpu:
        cdf = get_cpu_cdf(directory, osname, pat)
        plt.plot(*cdf, color='C{}'.format(i), label=label)
        i += 1
    plt.xlabel("CPU idle")
    plt.ylabel("Cumulative fraction")
    plt.xlim(80, 101)
    plt.ylim(0,1)
    plt.legend(loc="upper left", fontsize=8)
    plt.savefig("{}_base_cpu.png".format(osname))
    plt.clf()

    plt.figure(figsize=(6,4))
    plt.subplot(111)
    i = 0 
    for pat,label in rtt:
        rtt = get_rtt_cdf(directory, osname, pat)
        plt.plot(*rtt, color='C{}'.format(i), label=label)
        i += 1
    plt.xlabel("Round-trip time (milliseconds)")
    plt.ylabel("Cumulative fraction")
    plt.xlim(0, 0.5)
    plt.ylim(0, 1)
    if osname.startswith('pi'):
        plt.legend(loc="upper left", fontsize=8)
    else:
        plt.legend(loc="lower right", fontsize=8)
    plt.savefig("{}_base_rtt.png".format(osname))
    plt.clf()

    plt.figure(figsize=(6,4))
    plt.subplot(111)
    i = 0 
    lstyles = ['-','--','-.',':','-']
    for pat,label in hoplimits:
        if 'hops' not in pat:
            maxttl = 1
        else:
            mobj = re.search('(?P<maxttl>\d+)hops', pat)
            maxttl = int(mobj.group('maxttl'))
        for t in range(1,maxttl+1):
            rtt = get_rtt_cdf(directory, osname, pat, ttl=t)
            plt.semilogx(*rtt, color='C{}'.format(i), label=label.format(t))
            i += 1
            if i == 10:
                i = 0
    plt.xlabel("Round-trip time (milliseconds)")
    plt.ylabel("Cumulative fraction")
    #plt.xlim(0, 0.005)
    plt.ylim(0, 1)
    plt.legend(loc="lower right", fontsize=8)
    plt.savefig("{}_rtt_hops.png".format(osname))
    plt.clf()


if __name__ == '__main__':
    for xdir in ('pib','pi3','freebsd','linux'):
        plot_cdfs(os.path.join('baseline',xdir), xdir)
