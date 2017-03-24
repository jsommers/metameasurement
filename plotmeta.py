import sys
import argparse
import json
import os.path

import matplotlib.pyplot as plt
from cycler import cycler

def _gather_ts(metad, k):
    klist = k.split(':')
    if len(klist) > 2:
        return _gather_ts(metad[klist[0]], ':'.join(klist[1:]))

    assert(len(klist) == 2)
    if klist[0] not in metad:
        print("Couldn't find data key {}".format(k))
        sys.exit(-1)

    data = metad[klist[0]]
    dkey = klist[1]
    tslist = [ t[0] for t in data ]
    dlist = [ t[1][dkey] for t in data ]
    return tslist, dlist

def plotItems(inbase, metadata, keys):
    '''
    FIXME: As of now, if there are more than 4 subplots, the
    plots look ugly. To add position logic.
    '''
    f, axarr = plt.subplots(len(keys), sharex=True)
    color_cycle = cycler(c=['r', 'g', 'b'])
    ls_cycle = cycler('ls', ['-.', '--', '-', ':'])
    lw_cycle = cycler('lw', range(1, 4))

    sty_cycle = ls_cycle * (color_cycle + lw_cycle)
    styles = []
    for i, sty in enumerate(sty_cycle):
        styles.append(sty)

    for idx, key in enumerate(keys):
        ts, data = _gather_ts(metadata, key)
        axarr[idx].plot(ts, data, label=key, **styles[idx])
        axarr[idx].set_ylabel(key)

    plt.savefig("{}.png".format(inbase))

def plotGroups(inbase, metadata, keys):
    for key in keys:
        items = [s for s in _dump_keys(metadata) if key in str(s)]
        plotItems(inbase+"_"+key, metadata, items)

def plotAll(inbase, metadata):
    groups = list(set([s.split(":")[1] for s in _dump_keys(metadata)]))
    for group in groups:
        plotGroups(inbase, metadata, [group])

def _dump_keys(metad):
    items = []
    def _dump_helper(currkey, metad):
        xdict = metad[currkey]
        for k,v in xdict.items():
            if isinstance(v, dict):
                _dump_helper(':'.join((currkey,k)), v[k])
            elif isinstance(v, list):
                ts, obsdict = v.pop(0)
                for obskey in obsdict.keys():
                    items.append(':'.join((currkey,k,obskey)))

    _dump_helper('monitors', metad)
    return items

def main():
    parser = argparse.ArgumentParser(
            description='Plot measurement metadata')
    parser.add_argument('-i', '--item', dest='items', action='append', \
                        help='Include individual item in the plot, e.g., monitors:cpu:idle')
    parser.add_argument('-g', '--group', dest='groups', action='append', \
                        help='Include a group of items in the plot, e.g., \
                        rtt includes icmprtt and seq')
    parser.add_argument('-a', '--all', action='store_true', \
                        help='Plot all groups in separate subplots.')
    parser.add_argument('jsonmeta', nargs=1)
    args = parser.parse_args()

    infile = args.jsonmeta[0]
    with open(infile) as infileh:
        meta = json.load(infileh)

    inbase,ext = os.path.splitext(infile)
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
        print("Must include at least one item to plot.  Here are valid item strings:")
        items = _dump_keys(meta)
        print(items)
        sys.exit(-1)

if __name__ == '__main__':
    main()
