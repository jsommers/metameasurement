import json
import argparse
from statistics import mean, stdev, median
from math import isinf
import sys
import os.path

import matplotlib.pyplot as plt
from cycler import cycler

def _gather_ts(metad, k):
    group, key = k.split(":")
    tsList = []
    valList = []
    for ts, val in metad['monitors'][group]:
        if key in val.keys():
            tsList.append(ts)
            valList.append(val[key])
    return tsList, valList

def _gather_ts_rtt(metad, k):
    group, key = k.split(":")
    xlist = metad['monitors'][group][key]
    tsVal = [ts for ts, xd in xlist]
    rtt = [ xd['recv'] - xd['send'] for ts,xd in xlist if not isinf(xd['recv']) and not isinf(xd['send']) ]
    if rtt:
        return tsVal, rtt
    else:
        return tsVal, [None for i in range(len(tsVal))]

def plotItems(inbase, metadata, keys):
    f, axarr = plt.subplots(figsize=(len(keys)*4,len(keys)*4), nrows=len(keys), ncols=1, sharex=True, squeeze=False)
    color_cycle = cycler(c=['r', 'g', 'b'])
    ls_cycle = cycler('ls', ['-.', '--', '-', ':'])
    lw_cycle = cycler('lw', range(1, 4))
    sty_cycle = ls_cycle * (color_cycle + lw_cycle)
    styles = []
    for i, sty in enumerate(sty_cycle):
        styles.append(sty)

    for idx, key in enumerate(keys):
        ts = []
        data = []
        if key.startswith('rtt'):
            ts, data = _gather_ts_rtt(metadata, key)
        else:
            ts, data = _gather_ts(metadata, key)

        axarr[idx,0].plot(ts, data, label=key, **styles[idx])
        axarr[idx,0].grid()
        axarr[idx,0].set_ylabel(key)
    axarr[len(keys)-1,0].set_xlabel("Time (s)")

    plt.savefig("{}.png".format(inbase))

def plotGroups(inbase, metadata, keyList):
    for key in metadata['monitors'].keys():
        for rKey in keyList:
            if key in rKey and rKey!='rtt':
                l = metadata['monitors'][key]
                ts, obsdict = l.pop(0)
                newL = [rKey+":"+k for k in obsdict.keys()]
                plotItems(inbase+"_"+rKey, metadata, newL)
            if key.startswith(rKey) and rKey=='rtt':
                newL = []
                for rttkey in metadata['monitors'][key].keys():
                    if rttkey.startswith('ttl') or rttkey == 'ping':
                        newL.append(key+":"+rttkey)
                plotItems(inbase+"_"+rKey, metadata, newL)

def plotAll(inbase, metadata):
    groups = _dump_keys(metadata)
    plotGroups(inbase, metadata, groups)

def _dump_keys(metadata):
    keyList = []
    for key in metadata['monitors'].keys():
        if key.startswith('rtt'):
            keyList.append('rtt')
        else:
            keyList.append(key)
    return keyList

def main():
    parser = argparse.ArgumentParser(description='Plotting script - v2')
    parser.add_argument('-i', '--item', dest='items', action='append', \
                        help='Include individual item in the plot, e.g., monitors:cpu:idle')
    parser.add_argument('-g', '--group', dest='groups', action='append', \
                        help='Include a group of items in the plot, e.g., \
                        rtt includes rtt and seq')
    parser.add_argument('-a', '--all', action='store_true', \
                        help='Plot all groups in separate subplots.')
    parser.add_argument('jsonmeta', nargs=1)
    args = parser.parse_args()

    infile = args.jsonmeta[0]
    with open(infile) as infileh:
        meta = json.load(infileh)

    inbase, ext = os.path.splitext(infile)

    if args.items:
        print("Plotting items: {0}".format(args.items))
        plotItems(inbase+"_items", meta, args.items)
    elif args.groups:
        print("Plotting groups: {0}".format(args.groups))
        plotGroups(inbase, meta, args.groups)
    elif args.all:
        print("Plotting all items in all groups.")
        plotAll(inbase, meta)
    else:
        print("Must include at least one group or one item from the group to plot.  Here are valid groups:")
        items = _dump_keys(meta)
        print(items)
        sys.exit(-1)

if __name__ == '__main__':
    main()
