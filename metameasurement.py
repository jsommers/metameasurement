import sys
import re
import os
import asyncio
import signal
from time import time, strftime, gmtime
import functools
from ipaddress import IPv4Network
from collections import defaultdict
import logging
from statistics import mean, stdev
import argparse
import subprocess
import json

import matplotlib.pyplot as plt

from switchyard.lib.userlib import *
from switchyard import pcapffi
from localnet import *
from sysobservers import *

def _create_decoder():
    _dlt_to_decoder = {}
    _dlt_to_decoder[pcapffi.Dlt.DLT_EN10MB] = lambda raw: Packet(raw, first_header=Ethernet)
    _dlt_to_decoder[pcapffi.Dlt.DLT_NULL] = lambda raw: Packet(raw, first_header=Null)
    _null_decoder = lambda raw: RawPacketContents(raw)
    def decode(dlt, xbytes):
        try:
            pkt = _dlt_to_decoder[dlt](xbytes)
        except: # could be KeyError or failure in pkt reconstruction
            pkt = _null_decoder(xbytes)
        return pkt
    return decode

decode_packet = _create_decoder()

class MeasurementObserver(object):
    def __init__(self, debug, fileprefix):
        self._asyncloop = asyncio.SelectorEventLoop()
        asyncio.set_event_loop(self._asyncloop)
        self._asyncloop.add_signal_handler(signal.SIGINT, self._sig_catcher)
        self._asyncloop.add_signal_handler(signal.SIGTERM, self._sig_catcher)
        self._ports = {}
        self._ifinfo = self._routes = None
        self._arp_cache = {}
        self._arp_queue = asyncio.Queue()
        self._icmp_queue = asyncio.Queue()
        self._debug = debug
        self._log = logging.getLogger('mm')
        self._pid = os.getpid()
        self._monitors = {}
        self._mon_interval = 1.0
        self._done = False
        self._icmpseq = 1
        self._warmcooltime = 2
        self._fileprefix = fileprefix
        self._toolproc = None

        logging.basicConfig(format='%(asctime)s | %(name)s | %(levelname)s | %(message)s')

        if self._debug:
            logging.basicConfig(level=logging.DEBUG)
            self._log.setLevel(logging.DEBUG)
            self._asyncloop.set_debug(True)
        else:
            self._log.setLevel(logging.INFO)
            logging.basicConfig(level=logging.INFO)

    def add_port(self, ifname, filterstr=''):
        p = pcapffi.PcapLiveDevice(ifname, filterstr=filterstr)
        self._ports[ifname] = p
        self._asyncloop.add_reader(p.fd, 
            functools.partial(self._packet_arrival_callback, pcapdev=p))

    def add_monitor(self, name, sysobserver):
        self._monitors[name] = sysobserver
        asyncio.ensure_future(sysobserver())

    def _cleanup(self):
        # close pcap devices and get stats from them
        self._pcapstats = {}
        for ifname,pcapdev in self._ports.items():
            s = pcapdev.stats()
            self._pcapstats[ifname] = {'recv':s.ps_recv,
                'pcapdrop':s.ps_drop, 'ifdrop':s.ps_ifdrop}
            self._log.info("Closing {}: {}".format(ifname, s))
            pcapdev.close()
        self._asyncloop.stop()

    def _write_meta(self, commandline): 
        proc = subprocess.run("uname -a", shell=True, 
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        metadict = {}
        metadict['start'] = self._starttime
        metadict['end'] = self._endtime
        metadict['os'] = proc.stdout
        metadict['command'] = commandline
        try:
            metadict['commandoutput'] = self._toolfut.result()
            self._log.info("Command output: {}".format(self._toolfut.result()))
        except:
            metadict['commandoutput'] = "Error: command did not start and/or complete"
            self._log.info("Error: command did not start and/or complete.")

        metadict['interface_info'] = self._pcapstats

        metadict['monitors'] = {}
        for k,m in self._monitors.items():
            metadict['monitors'][k] = m.results.all()
            self._log.info("Monitor summary {}: {}".format(k, m.results.summary(mean)))
        metadict['localnet'] = {} 
        metadict['localnet']['hops_monitored'] = 1 # FIXME -> generalize this
        metadict['localnet']['icmpresults'] = self._monfut.result()
        self._log.info("Local network performance summary: {}".format(self._monfut.result()))

        timestr = strftime("%Y%m%d_%H%M%S", gmtime(self._starttime))
        filebase = "{}_{}".format(self._fileprefix, timestr)

        # FIXME: this should be factored out 
        self._plotit = True
        if self._plotit:
            ts1,delay = self._icmpresults.timeseries('icmprtt')
            ts2,cpuidle = self._monitors['cpu'].results.timeseries('idle')

            fig,rttax = plt.subplots()
            fig.subplots_adjust(right=0.75)
            cpuax = rttax.twinx()

            p1, = rttax.plot(ts1, delay, "b-", label="RTT to first hop")
            p2, = cpuax.plot(ts2, cpuidle, "r-", label="CPU idle")

            rttax.set_xlabel("Time (sec)")
            rttax.set_ylabel("RTT (sec)")
            cpuax.set_ylabel("Idle CPU (%)")

            rttax.set_ylim(0, round(max(delay) * 1.25, 3))
            cpuax.set_ylim(0, 100)

            rttax.yaxis.label.set_color(p1.get_color())
            cpuax.yaxis.label.set_color(p2.get_color())

            rttax.legend([p1,p2], [p.get_label() for p in [p1,p2]])
            plt.savefig("{}.png".format(filebase))

        if self._debug:
            print("Metadata to write:", metadict)
        else:
            with open("{}.json".format(filebase), 'w') as outfile:
                json.dump(metadict, outfile)

    def _shutdown(self, future):
        self._log.debug("tool done; shutting down")
        if future:
            self._log.debug("result: {}".format(future.result()))
        self._asyncloop.call_later(self._warmcooltime, self._cleanup)
        self._done = True
        if self._toolproc and self._toolproc.returncode is None:
            self._toolproc.terminate()
        for m in self._monitors.values():
            m.stop()
        for t in asyncio.Task.all_tasks():
            t.cancel()

    def _sig_catcher(self, *args):
        self._shutdown(None)

    def _packet_arrival_callback(self, pcapdev=None):
        while True:
            p = pcapdev.recv_packet_or_none()
            if p is None:
                break

            name = pcapdev.name
            pkt = decode_packet(pcapdev.dlt, p.raw)
            ts = p.timestamp
            ptup = (name,ts,pkt)

            if pkt.has_header(Arp) and \
              pkt[Arp].operation == ArpOperation.Reply: 
                a = pkt[Arp]
                #self._log.debug("Got ARP response: {}-{}".format(a.senderhwaddr, a.senderprotoaddr))
                self._arp_queue.put_nowait((a.senderhwaddr, a.senderprotoaddr))
            elif pkt.has_header(ICMP):
                #self._log.debug("Got something ICMP")
                if (pkt[ICMP].icmptype == ICMPType.EchoReply and \
                    pkt[ICMP].icmpdata.identifier == self._icmpident):
                    seq = pkt[ICMP].icmpdata.sequence
                    #self._log.debug("Got ICMP response on {} at {}: {}".format(name, ts, pkt))
                    self._icmp_queue.put_nowait((ts,seq,pkt[IPv4].src,pkt))
                elif pkt[ICMP].icmptype == ICMPType.TimeExceeded:
                    p = Packet(pkt[ICMP].icmpdata.data, first_header=IPv4) 
                    if p[ICMP].icmpdata.identifier == self._icmpident:
                        #self._log.debug("Got ICMP excerr on {} at {}: {}".format(name, ts, pkt))
                        #self._log.debug("orig pkt: {}".format(p))
                        seq = p[ICMP].icmpdata.sequence
                        ident = p[ICMP].icmpdata.identifier
                        self._icmp_queue.put_nowait((ts,seq,pkt[IPv4].src,pkt))
                elif pkt[ICMP].icmptype == ICMPType.EchoRequest and \
                    pkt[ICMP].icmpdata.identifier == self._icmpident:
                        #self._log.debug("Got our request pkt on {} at {}: {}".format(name, ts, pkt))
                        seq = pkt[ICMP].icmpdata.sequence
                        self._icmp_queue.put_nowait((ts,seq,pkt[IPv4].src,pkt))
            else:
                self._log.debug("Ignoring packet from {}: {}".format(name, pkt))

    async def _run_tool(self, commandline, future):
        create = asyncio.create_subprocess_shell(commandline, 
                                                 stdout=asyncio.subprocess.PIPE,
                                                 stderr=asyncio.subprocess.PIPE)
        try:
            self._toolproc = await create
        except asyncio.CancelledError:
            return
        self._log.debug("Measurement tool started with pid {}".format(self._toolproc.pid))
        try:
            output = await self._toolproc.communicate() # assumes that data to read is not too large
        except asyncio.CancelledError:
            return
        if not future.cancelled():
            future.set_result({'returncode': self._toolproc.returncode,
                               'stdout': output[0].decode('utf8'),
                               'stderr': output[1].decode('utf8')})

    def _send_packet(self, intf, pkt):
        assert(intf in self._ports)
        assert(isinstance(pkt, Packet))
        pcapdev = self._ports[intf]
        pcapdev.send_packet(pkt.to_bytes())

    async def _do_arp(self, dst, intf):
        if dst in self._arp_cache:
            return self._arp_cache[dst]
        ifinfo = self._ifinfo[intf]
        arpreq = create_ip_arp_request(ifinfo.ethsrc, 
            ifinfo.ipsrc.ip, dst)
        fareth = "00:00:00:00:00:00"
        self._send_packet(ifinfo.name, arpreq)
        while True:
            try:
                ethaddr,ipaddr = await self._arp_queue.get()
            except asyncio.CancelledError:
                break
            self._arp_cache[ipaddr] = ethaddr
            if ipaddr == dst:
                break

        return ethaddr

    async def _ping(self, dst):
        nh = self._routes[dst]
        try:
            ethaddr = await self._do_arp(nh.nexthop, nh.interface)
        except asyncio.CancelledError:
            return
        thisintf = self._ifinfo[nh.interface]
        self._icmpident = self._pid%65535
        pkt = Ethernet(src=thisintf.ethsrc, dst=ethaddr) + \
            IPv4(src=thisintf.ipsrc.ip, dst=dst, protocol=IPProtocol.ICMP,
                ttl=2) + \
            ICMP(icmptype=ICMPType.EchoRequest,
                identifier=self._icmpident,
                sequence=self._icmpseq)
        self._log.debug("Emitting icmp echo request: {}".format(pkt))
        self._icmpseq += 1
        if self._icmpseq == 65536:
            self._icmpseq = 1
        self._send_packet(nh.interface, pkt)

    async def _ping_collector(self, fut):
        A = ICMPType.EchoRequest
        B = ICMPType.TimeExceeded
        seqhash = {A: {}, B: {}}
        r = self._icmpresults = ResultsContainer()

        while not self._done:
            try:
                ts,seq,src,pkt = await self._icmp_queue.get()
            except asyncio.CancelledError:
                break
            xhash = seqhash[pkt[ICMP].icmptype]
            xhash[seq] = ts
            if seq in seqhash[A] and seq in seqhash[B]:
                rtt = seqhash[B].pop(seq) - seqhash[A].pop(seq)
                r.add_result({'icmprtt':rtt,'seq':seq})


        echo = seqhash[A]
        exc = seqhash[B]

        for seq in sorted(echo.keys()):
            if seq in exc:
                rtt = exc[seq] - echo[seq]
            else:
                rtt = float('inf')
            r.add_result({'icmprtt':rtt,'seq':seq})

        self._log.debug("icmpsummary: {}".format(r.summary(mean)))
        fut.set_result(r.all())

    async def _monitor_first_n_hops(self, future):
        asyncio.ensure_future(self._ping_collector(self._monfut))
        while not self._done:
            try:
                # direct echo requests toward Google public DNS anycast 
                t = await self._ping('8.8.8.8')
            except asyncio.CancelledError:
                break
            try:
                await asyncio.sleep(self._mon_interval)
            except asyncio.CancelledError:
                break
            cpuidle = float(self._monitors['cpu'].results.compute(mean, 'idle', 2))
            self._log.info("Current idle cpu {}".format(cpuidle))
            
            # if cpuidle < 30:
            #     self._mon_interval *= 2.0
            # elif cpuidle > 70:
            #     self._mon_interval /= 2.0

            # for m in self._monitors.values():
            #     m.set_interval(self._mon_interval)

    def _start_tool(self, cmdline):
        asyncio.ensure_future(self._run_tool(cmdline, self._toolfut))
        self._toolfut.add_done_callback(self._shutdown)
        
    def run(self, commandline):
        self._starttime = time()
        self._log.info("Starting metadata measurement with verbose {} and commandline <{}>".format(
            self._debug, commandline))

        self._ifinfo = get_interface_info(self._ports.keys())
        self._routes = get_routes(self._ifinfo)

        # debugging: dump out all interface and route info
        # for intf in self._ifinfo:
        #     print("{} -> {}".format(intf, self._ifinfo[intf]))
        # for prefix in self._routes:
        #     print("{} -> {}".format(prefix, self._routes[prefix]))

        self._monfut = asyncio.Future()
        xfut = asyncio.Future()
        asyncio.ensure_future(self._monitor_first_n_hops(xfut))

        self._toolfut = asyncio.Future()
        self._cmdstart = self._asyncloop.call_later(self._warmcooltime, 
            self._start_tool, commandline)

        try:
            self._asyncloop.run_forever()
        finally:
            self._asyncloop.close()

        # if not self._toolfut.cancelled():
        #     print("Tool future: {}".format(self._toolfut.result()))
        # if not self._monfut.cancelled():
        #     print("Mon future: {}".format(self._monfut.result()))

        self._endtime = time()
        self._write_meta(commandline)


def main():
    parser = argparse.ArgumentParser(
            description='Automatic generation of active measurement metadata')
    parser.add_argument('-d', '-v', '--verbose', '--debug', 
                        dest='verbose', action='store_true', default=False,
                        help='Turn on verbose/debug output.')
    parser.add_argument('-f', '--fileprefix', dest='fileprefix', type=str, default='metadata',
                        help='Prefix for filename that includes metadata for a given run.')
    parser.add_argument('-c', '--command', dest='commandline', type=str, default='sleep 5',
                        help='The full command line for running an active measurement tool'
                             ' (note that the command line almost certainly needs to be quoted)')
    args = parser.parse_args()

    m = MeasurementObserver(args.verbose, args.fileprefix)
    m.add_port('en0', 'icmp or arp')
    m.add_monitor('cpu', SystemObserver(CPUDataSource(), 1))
    m.add_monitor('io', SystemObserver(IODataSource(), 3))
    m.add_monitor('netstat', SystemObserver(NetIfDataSource('en0'), 1))
    m.add_monitor('mem', SystemObserver(MemoryDataSource(), 3))
    commandline = "sleep 5"
    m.run(args.commandline)

if __name__ == '__main__':
    main()

