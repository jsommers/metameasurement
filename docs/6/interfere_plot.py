import json
import subprocess
import statistics
import matplotlib.pyplot as plt
from math import isinf
import argparse
import re
import time
import sys
from scipy.stats import ks_2samp
from scipy.stats.mstats import ks_twosamp

MAXHOPSTOPLOT=2

_names = {
'8.8.8.8':'8.8.8.8',

# dns root servers
'198.41.0.4':'A',
'192.228.79.201':'B',
'192.33.4.12':'C',
'199.7.91.13':'D',
'192.203.230.10':'E',
'192.5.5.241':'F',
# G root is well-known not to respond to pings
# 192.112.36.4
'198.97.190.53':'H',
'192.36.148.17':'I',
'192.58.128.30':'J',
'193.0.14.129':'K',
'199.7.83.42':'L',
'202.12.27.33':'M',
# 0.pool.ntp.org
'128.138.141.172':'0a',
'45.33.84.208':'0b',
'24.124.0.251':'0c',
'38.229.71.1':'0d',
# 1.pool.ntp.org
'199.101.100.221':'1a',
'66.228.59.187':'1b',
'69.167.160.102':'1c',
'173.255.246.13':'1d',
# 2.pool.ntp.org
'199.48.128.10':'2a',
'72.87.88.202':'2b',
'97.116.42.238':'2c',
'104.131.155.175':'2d',
# 3.pool.ntp.org
'23.239.24.67':'3a',
'69.89.207.99':'3b',
'216.218.254.202':'3c',
'204.11.201.12':'3d',
}

class LoadPeriods(object):
    def __init__(self, slist):
        self._tlist = slist        

    def __call__(self, t):
        '''
        If given timestamp t is within an "on" interval
        return True, otherwise return False.
        '''
        if not self._tlist:
            return False

        for a,b in self._tlist:
            if a <= t <= b:
                return True
        return False

    def __str__(self):
        return str(self._tlist)

    def filter(self, tlist, dlist, off=True):
        if off:
            return [ d for t,d in zip(tlist, dlist) if not self.__call__(t) ]
        else:
            return [ d for t,d in zip(tlist, dlist) if self.__call__(t) ]

class PingData(object):
    def __init__(self, jsondict, timerange):
        self._dst = jsondict['dst']
        self._src = jsondict['src']
        self._data = {}
        self._start = jsondict['start']['sec'] + jsondict['start']['usec']/1000000

        if timerange:
            withinrange = lambda t: self._start+timerange[0] <= t <= self._start+timerange[1]
        else:
            withinrange = lambda t: True

        for d in jsondict['responses']:
            seq = d['seq']
            rtt = d['rtt']
            if 'tx' in d:
                send = d['tx']['sec'] + d['tx']['usec'] / 1000000
            else:
                send = self._start + seq - 1

            if withinrange(send):
                self._data[seq] = (send,rtt,seq)

    @property
    def dst(self):
        return self._dst

    def samples(self, oncensor=None, off=True):
        if oncensor is None:
            oncensor = LoadPeriods([])
        if off:
            return [ s[1] for s in self._data.values() if not oncensor(s[0]) ]
        else:
            return [ s[1] for s in self._data.values() if oncensor(s[0]) ]

    def timeseries(self, oncensor=None, relative=False):
        if oncensor is None:
            oncensor = LoadPeriods([])
        stval = 0
        if relative:
            stval = self._start
        tvals = [ s[0]-stval for s in self._data.values() if not oncensor(s[0]-self._start) ]
        dvals = [ s[1] for s in self._data.values() if not oncensor(s[0]-self._start) ]
        seq = [ (s[0]-stval,s[2]) for s in self._data.values() ]
        _,prev = seq.pop(0)
        losst = []

        for t,s in seq:
            while prev+1 != s:
                losst.append(t)
                t += 1
                prev += 1
            prev=s
        return tvals,dvals,losst,[0]*len(losst)

    def __len__(self):
        return len(self._data)

    def __str__(self):
        m = 0.0
        d = 0.0
        if len(self._data):
            m = statistics.mean(self.samples()) 
            d = statistics.stdev(self.samples())
        return "{}->{} {} {:.2f} ({:.3f})".format(self._src, self._dst, len(self._data), m, d)

    @property
    def start(self):
        return self._start

    @start.setter
    def start(self, value):
        self._start = value

    @property
    def end(self):
        return max([ s[0] for s in self._data.values() ])
            

def dotsplot(pingdata, ipaddr, metartts, onoff, outname, servername, metastart, metaend, pingstart, pingend, timerange, maxrtt):
    fig = plt.figure(figsize=(8,4))
    ax = fig.add_subplot(111, ylabel='RTT (milliseconds)', xlabel='Time (s)')

    tval,dval,tloss,lossv = pingdata.timeseries()

    ax.plot(tval, dval, marker='.', linestyle='', color='k', label='Ping {}'.format(ipaddr))
    ax.plot(tloss, [-1]*len(tloss), marker='x', linestyle='', color='k', label='Ping loss')

    for i,metakey in enumerate(sorted(metartts.keys())):
        metats, metartt, metatsloss = metartts[metakey]
        ax.plot(metats, metartt, marker='.', linestyle='', color='C{}'.format(i), label=metakey, zorder=1)
        ax.plot(metatsloss, [-1.5]*len(metatsloss), marker='x', linestyle='', color='C{}'.format(i), label='{} loss'.format(metakey), zorder=1)


    for st,en in onoff:
        ax.axvspan(st,en, color='grey', alpha=0.1, fill=True, zorder=0)

    if maxrtt == 0:
        maxrtt = max(dval)*1.25

    ax.set_ylim(-2, maxrtt)
    minx = min(pingstart, metastart)
    maxx = max(pingend, metaend)
    if timerange:
        maxx = minx + timerange[1]
        minx = minx + timerange[0]
    ax.set_xlim(minx, maxx)

    _, lablist = ax.get_legend_handles_labels()
    # ncol = len(lablist) // 2
    ncol = 3
    ax.legend(loc='upper left', ncol=ncol, fontsize=8)
    plt.tight_layout()
    
    plt.savefig("{}_{}.png".format(outname, servername), bbox_inches='tight')

def doboxplot(wartsdata, someta, outname):
    fig = plt.figure()
    ax = fig.add_subplot(111, ylabel='RTT (milliseconds)', xlabel='Server target')

    labels = []
    samples = []
    for sokey in sorted(someta.keys()):
        t,r,tl = someta[sokey]
        labels.append(sokey)
        samples.append(r)

    for dst,xd in wartsdata.items():
        labels.append("scamper {}".format(_names[dst]))
        samples.append(xd.samples())

    ax.boxplot(samples, labels=labels, showfliers=False)
    ax.set_ylim(0,)

    plt.tight_layout()
    plt.savefig("{}_boxplot.png".format(outname), bbox_inches='tight')

def loadmeta(fname):
    with open(fname) as infile:
        d = json.loads(infile.read())
    return d

def get_timertt(xli, validtime):
    tval = []
    rval = []
    tlval = []
    prevseq = xli[0][1]['seq'] - 1
    for ts,xd in xli:
        if not validtime(ts):
            continue

        if xd['rtt'] < 0:
            continue
        ut = xd['usersend']
        if isinf(xd['wiresend']) or isinf(xd['wirerecv']):
            tlval.append(ut)
        elif not isinf(xd['wiresend']):
            tval.append(xd['wiresend'])
            rval.append(xd['rtt']*1000) # -> sec->msec

    return tval,rval,tlval

def compute_meta_rtts(d, metastart, timerange):
    # assumption: only one hop-limited prober was used, 0 or more
    # ping probers may have been used

    if timerange:
        withinrange = lambda t: metastart+timerange[0] <= t <= metastart+timerange[1]
    else:
        withinrange = lambda t: True

    rtts = {}
    for k in d['monitors'].keys():
        if k.startswith('rtt'):
            m = d['monitors'][k] 
            if m['probe_config']['probetype'] == 'hoplimited':
                for k,dv in m.items():
                    if k.startswith('ttl'):
                        mobj = re.match('ttl_(?P<ttl>\d+)', k)
                        xttl = int(mobj.group('ttl'))
                        if xttl <= MAXHOPSTOPLOT:
                            t,r,tl = get_timertt(m[k], withinrange)
                            rtts['SoMeta Hop {}'.format(xttl)] = t,r,tl
            else:
                t,r,tl = get_timertt(m['ping'], withinrange)
                k = 'SoMeta Ping {}'.format(m['probe_config']['dest'])
                rtts[k] = t,r,tl
    return rtts

def loadonoff(fname):
    on = []
    if not fname:
        return on

    ison = False
    with open(fname) as infile:
        for line in infile:
            mobj = re.match('^(\d{14}) (on|off) for', line)
            if mobj:
                tstr = mobj.groups()[0]
                tval = time.strptime(tstr, "%Y%m%d%H%M%S")
                onoff = mobj.groups()[1]
                if onoff == 'off' and ison:
                    ison = False
                    end = tval
                    on.append( (time.mktime(start),time.mktime(end)) )
                elif onoff == 'on':
                    ison = True
                    start = tval
                #print(tval,onoff)
    return on

def mkcdf(values):
    # precondition: values must be sorted!
    ticks = min(len(values), 100)
    idxli = [ float(x)/ticks for x in range(0,ticks) ]
    xvals = []
    nval = len(values)
    for idx in idxli:
        pos = int(idx * nval)
        xvals.append(values[pos])
    idxli.append(1.0)
    xvals.append(values[-1])
    return xvals,idxli

def cdfplot(pingdata, ipaddr, metartts, metanonertts, onoff, outname, servername, metastart, metaend, pingstart, pingend, maxrtt, nosplit, cdfpanels):

    fig = plt.figure(figsize=(6,4))
    c = LoadPeriods(onoff)
    ax = fig.add_subplot(1, 1, 1, ylabel='Cumulative fraction', xlabel='RTT (milliseconds)')

    hcval = 0
    for i,metakey in enumerate(sorted(metartts.keys())):
        metats, metartt, metatsloss = metartts[metakey]
        x, y = mkcdf(sorted(metartt))
        if 'Ping' in metakey:
            cval = 'grey'
            lstyle = '-'
        else:
            cval = "C{}".format(hcval)
            hcval += 1
            lstyle = '-'

        ax.semilogx(x, y, color=cval, linestyle=lstyle, label='{}'.format(metakey))

    hcval = 0
    if metanonertts and not cdfpanels:
        for i,metakey in enumerate(sorted(metanonertts.keys())):
            metats, metartt, metatsloss = metanonertts[metakey]
            if 'Ping' in metakey:
                cval = 'grey'
                lstyle = '-.'
            else:
                cval = "C{}".format(hcval)
                hcval += 1
                lstyle = '-.'
            x, y = mkcdf(sorted(metartt))
            ax.semilogx(x, y, color=cval, linestyle=lstyle, label='{}\n(no load experiment)'.format(metakey))

    pingoff = pingdata.samples()
    x,y = mkcdf(sorted(pingoff))
    ax.semilogx(x, y, color='k', label='Ping {}'.format(ipaddr))

    ax.set_ylim(0,1)
    if maxrtt > 0 and not cdfpanels:
        ax.set_xlim(0.1, maxrtt) 
    elif cdfpanels:
        ax.set_xlim(0,)
    ax.legend(loc='lower right', fontsize=8)
    plt.tight_layout()
    plt.savefig("{}_cdf.png".format(outname), bbox_inches='tight')

def main(wartsin, metain, loadin, outname, args):

    timerange = None
    if args.timerange:
        timerange = tuple(map(int, args.timerange.split(',')))
        assert(timerange[0] >= 0)
        assert(timerange[1] > timerange[0])

    wartsdata = {}
    p = subprocess.run("sc_warts2json < {}".format(wartsin), shell=True, stdout=subprocess.PIPE, universal_newlines=True)
    lines = p.stdout.split('\n')
    minstart = None
    for i in range(len(lines)):
        if len(lines[i].strip()):
            d = PingData(json.loads(lines[i]), timerange)
            if not len(d):
                print("No samples for dest {}".format(d.dst))
                continue
            wartsdata[d.dst] = d
            if minstart is not None and d.start is not None:
                minstart = min(d.start, minstart)
            elif d.start is not None:
                minstart = d.start

    if len(wartsdata) == 0:
        print("No data?!")
        return

    d = loadmeta(metain)
    metastart = d['start']
    metaend = d['end']
    metartts = compute_meta_rtts(d, metastart, timerange)

    metanonertts = {}
    if args.metanone:
        dnone = loadmeta(args.metanone)
        metanonertts = compute_meta_rtts(dnone, dnone['start'], timerange)

    onoff = loadonoff(loadin)
    print(onoff)

    # reset start time for all dests based on global start time
    endlist = []
    for dst,d in wartsdata.items():
        d.start = minstart
        endlist.append(d.end)
        print(d)
    pingend = max(endlist)
    pingstart = minstart

    doboxplot(wartsdata, metartts, outname) 

    for ipaddr,servername in _names.items():
        if ipaddr not in wartsdata:
            continue
        pingdata = wartsdata[ipaddr]

        dotsplot(pingdata, ipaddr, metartts, onoff, outname, servername, metastart, metaend, pingstart, pingend, timerange, args.maxrtt)

        cdfplot(pingdata, ipaddr, metartts, metanonertts, onoff, outname, servername, metastart, metaend, pingstart, pingend, args.maxrtt, args.nosplit, args.cdfpanels)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--warts', dest='warts', default='',
        type=str,
        help='Name of warts file from which to read data')
    parser.add_argument('--meta', dest='meta', default='',
        type=str,
        help='Name of metadata json file from which to read data')
    parser.add_argument('--metanone', dest='metanone', default='',
        type=str,
        help='Name of metadata json file with results for NO load (to plot alongside load curves)')
    parser.add_argument('--load', dest='load', default='',
        type=str,
        help="Name of text file that contains load on/off timestamps")
    parser.add_argument('--outname', '-o', default='pingplots',
        help="Name of output plot")
    parser.add_argument('--maxrtt', dest='maxrtt', type=int,
        default=0,
        help="Max RTT value to plot in timeseries plot")
    parser.add_argument('--maxttl', dest='xmaxttl', type=int,
        default=2,
        help="Max TTL value to plot for SoMeta hop-limited probes")
    parser.add_argument('--timerange', dest='timerange', type=str,
        default=None, 
        help="Set a (relative) time range to show in plots")
    parser.add_argument('--nosplit', default='', type=str,
        help="Don't split on/off in CDF plots")
    parser.add_argument('--cdfpanels', default=False, action='store_true',
        help="Plot CDFs in separate panels (not shared axes)")

    args=parser.parse_args()
    if not args.warts or not args.meta:
        parser.print_usage()
        sys.exit()

    MAXHOPSTOPLOT=args.xmaxttl

    main(args.warts, args.meta, args.load, args.outname, args)
