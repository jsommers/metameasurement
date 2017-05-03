import sys
import json
import argparse
from statistics import mean, stdev, median
from math import isinf
import sys
import os.path

import matplotlib.pyplot as plt
from cycler import cycler

def _gather_ts(rawdlist, key):
    ts = [ ts for ts,_ in rawdlist ]
    vals = [ xd[key] for ts,xd in rawdlist ]
    return ts, vals

def _gather_ts_rtt(rawdlist, xkey):
    tsval = []
    rtt = []
    for i in range(len(rawdlist)):
        ts, xd = rawdlist[i]
        rval = xd['rtt']
        if isinf(rval) or rval < 0:
            continue
        tsval.append(ts)
        rtt.append(rval)
    return tsval, rtt

def plotItems(inbase, datamap, keys):
    f, axarr = plt.subplots(figsize=(len(keys)*6,len(keys)*4), nrows=len(keys), ncols=1, sharex=True, squeeze=False)
    # color_cycle = cycler(c=[ 'C{}'.format(i) for i in range(3) ])
    # ls_cycle = cycler('ls', ['-.', '--', '-', ':'])
    # lw_cycle = cycler('lw', range(1, 4))
    # sty_cycle = ls_cycle * (color_cycle + lw_cycle)
    # styles = []
    # for i, sty in enumerate(sty_cycle):
    #     styles.append(sty)

    for idx, key in enumerate(keys):
        ts = []
        data = []
        rawdlist = datamap[key]
        dkey = key.split(':')[-1]
        if key.endswith('rtt'):
            ts, data = _gather_ts_rtt(rawdlist, dkey)
        elif key.endswith('ipsrc'):
            continue
        else:
            ts, data = _gather_ts(rawdlist, dkey)

        # axarr[idx,0].plot(ts, data, label=dkey, **styles[idx], marker='o')
        # axarr[idx,0].plot(ts, data, label=dkey, color='C{}'.format(idx))

        maxD = max(data)
        minD = min(data)
        axarr[idx,0].scatter(ts, data, label=dkey, color='C{}'.format(idx), marker='o')
        axarr[idx,0].set_ylim([minD - 0.1 * minD, maxD + 0.1 * maxD])
        axarr[idx,0].grid()
        axarr[idx,0].set_ylabel(dkey)
    axarr[len(keys)-1,0].set_xlabel("Time (s)")

    plt.tight_layout()
    plt.savefig("{}.png".format(inbase))

def plotGroups(inbase, datamap, keyList):
    for k in keyList:
        matchitems = []
        matchkey = "{}:".format(k)
        for dkey in datamap.keys():
            if dkey.startswith(matchkey):
                matchitems.append(dkey)
        plotItems('_'.join((inbase, k)), datamap, matchitems)

def plotAll(inbase, datamap):
    groups = _dump_keys(datamap)
    plotGroups(inbase, datamap, groups)

def _dump_keys(datamap, dumpfull=False):
    rv = []
    for k in datamap.keys():
        if dumpfull:
            print(k)
        else:
            kbase = k.split(':')
            if kbase[0] not in rv:
                rv.append(kbase[0])
    return rv

def _get_subkeys(xdata, isrtt):
    keymap = {}
    if isrtt:
        assert(isinstance(xdata, dict))
        for k in xdata.keys():
            if k == 'ping' or k.startswith('ttl'):
                xlist = xdata[k]
                ts, xd = xlist[0]
                for subkey in xd.keys():
                    xkey = '{}:{}'.format(k, subkey)
                    keymap[xkey] = xlist
    else:
        assert(isinstance(xdata, list))
        ts, xd = xdata[0]
        for xkey in xd.keys():
            keymap[xkey] = xdata
    return keymap

def _make_key_map(metadata):
    xmap = {}
    xrtt = 0
    for basekey in metadata['monitors'].keys():
        rttmon = False
        if basekey.startswith('rtt'):
            keyname = 'rttmon{}'.format(xrtt)
            xrtt += 1
            rttmon = True
        else:
            keyname = basekey
        for sk, xli in  _get_subkeys(metadata['monitors'][basekey], rttmon).items():
            xmap['{}:{}'.format(keyname, sk)] = xli
    return xmap

def main():
    parser = argparse.ArgumentParser(description='Plotting script - v2')
    parser.add_argument('-i', '--item', dest='items', action='append',
                        help='Include individual item in the plot, e.g., monitors:cpu:idle')
    parser.add_argument('-g', '--group', dest='groups', action='append',
                        help='Include a group of items in the plot, e.g., \
                        rtt includes rtt and seq')
    parser.add_argument('-a', '--all', action='store_true',
                        help='Plot all groups in separate subplots.')
    parser.add_argument('-l', '--list', action='store_true',
                        help='List all data keys that can be plotted')
    parser.add_argument('jsonmeta', nargs=1)
    args = parser.parse_args()

    infile = args.jsonmeta[0]
    with open(infile) as infileh:
        meta = json.load(infileh)

    inbase, ext = os.path.splitext(infile)

    datamap = _make_key_map(meta)

    if args.items:
        print("Plotting items: {0}".format(args.items))
        plotItems(inbase+"_items", datamap, args.items)
    elif args.groups:
        print("Plotting groups: {0}".format(args.groups))
        plotGroups(inbase, datamap, args.groups)
    elif args.all:
        print("Plotting all items in all groups.")
        plotAll(inbase, datamap)
    elif args.list:
        _dump_keys(datamap, dumpfull=True)
    else:
        print("Must include at least one group or one item from the group to plot.  Here are valid groups: {}".format(', '.join(_dump_keys(datamap))))
        sys.exit(-1)

if __name__ == '__main__':
    main()
