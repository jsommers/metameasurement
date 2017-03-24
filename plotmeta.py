import sys
import argparse
import json
import os.path

import matplotlib.pyplot as plt

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

def plotit(inbase, metadata, keys):
    fig,ax1 = plt.subplots()

    k1 = keys.pop()

    ts1, data1 = _gather_ts(metadata, k1)
    p1, = ax1.plot(ts1, data1, "b-", label=k1)
    plines = [p1]

    ax1.set_xlabel("Time (sec)")
    ax1.set_ylabel(k1)
    ax1.set_ylim(0, round(max(data1) * 1.25, 3))
    ax1.yaxis.label.set_color(p1.get_color())

    # FIXME only handle up to two keys/axes at this point
    if len(keys):
        k2 = keys.pop()
        ts2, data2 = _gather_ts(metadata, k2)
        axx = ax1.twinx()
        p2, = axx.plot(ts2, data2, "r-", label=k2)
        plines.append(p2)

        axx.set_ylabel(k2)

        axx.set_ylim(0, round(max(data2) * 1.25, 3))

        axx.yaxis.label.set_color(p2.get_color())

    ax1.legend(plines, [p.get_label() for p in plines])
    plt.savefig("{}.png".format(inbase))

def _dump_keys(metad):
    def _dump_helper(currkey, metad):
        xdict = metad[currkey]
        for k,v in xdict.items():
            if isinstance(v, dict):
                _dump_helper(':'.join((currkey,k)), v[k])
            elif isinstance(v, list):
                ts, obsdict = v.pop(0)
                for obskey in obsdict.keys():
                    print(':'.join((currkey,k,obskey)))

    _dump_helper('monitors', metad)

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
        print("{0}".format(args.items))
        plotit(inbase, meta, args.items)
    elif args.groups:
        print("{0}".format(args.groups))
    elif args.all:
        print("{0}".format(args.all))
    else:
        print("Must include at least one item to plot.  Here are valid item strings:")
        _dump_keys(meta)
        sys.exit(-1)

if __name__ == '__main__':
    main()
