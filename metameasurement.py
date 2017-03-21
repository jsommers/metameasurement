import sys
import re
import os
import asyncio
import signal
from time import time
import functools
from ipaddress import IPv4Network
from collections import defaultdict
import logging
from statistics import mean, stdev

from switchyard.lib.userlib import *
from switchyard import pcapffi

from localnet import get_interface_info, get_routes
from sysobservers import SystemObserver, TopCommandParser, IostatCommandParser, NetstatIfaceStatsCommandParser, ResultsContainer

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
    def __init__(self, debug):
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
        logging.basicConfig(format='%(asctime)s | %(name)s | %(levelname)s | %(message)s')

        if self._debug:
            logging.basicConfig(level=logging.DEBUG)
            self._log.setLevel(logging.DEBUG)
            self._asyncloop.set_debug(True)
        else:
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
        # close pcap devices
        for ifname,pcapdev in self._ports.items():
            self._log.info("Closing {}: {}".format(ifname, pcapdev.stats()))
            pcapdev.close()
        self._asyncloop.stop()
        for k,m in self._monitors.items():
            self._log.info("Monitor summary {}: {}".format(k, m.results.summary(mean)))

    def _shutdown(self, future):
        self._log.debug("tool done; shutting down")
        if future:
            self._log.debug("result: {}".format(future.result()))
        self._asyncloop.call_soon(self._cleanup)
        self._done = True
        if self._toolproc.returncode is None:
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
                                                 stderr=asyncio.subprocess.STDOUT)
        self._toolproc = await create
        print("process id {} started".format(self._toolproc.pid))
        output = await self._toolproc.communicate() # assumes that data to read is not too large
        print("process output: {}".format(output))
        print("process returnval: {}".format(self._toolproc.returncode))
        if not future.cancelled():
            future.set_result(self._toolproc.returncode)

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
            ethaddr,ipaddr = await self._arp_queue.get()
            self._arp_cache[ipaddr] = ethaddr
            if ipaddr == dst:
                break
        return ethaddr

    async def _ping(self, dst):
        #self._log.debug("send ping to {}".format(dst))
        nh = self._routes[dst]
        #self._log.debug("ARPing for next hop: {}".format(nh))
        ethaddr = await self._do_arp(nh.nexthop, nh.interface)
        #self._log.debug("Got ethaddr for nh: {}".format(ethaddr))
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
        seqhash = {ICMPType.EchoRequest: {},
                   ICMPType.TimeExceeded: {} }
        r = ResultsContainer()
        while not self._done:
            try:
                ts,seq,src,pkt = await self._icmp_queue.get()
            except:
                break
            xhash = seqhash[pkt[ICMP].icmptype]
            xhash[seq] = ts

        echo = seqhash[ICMPType.EchoRequest]
        exc = seqhash[ICMPType.TimeExceeded]

        for seq in sorted(echo.keys()):
            if seq in exc:
                rtt = exc[seq] - echo[seq]
                r.add_result({'icmprtt':rtt,'seq':seq})

        print(r.summary(mean))
        fut.set_result(r.summary(mean))

    async def _monitor_first_n_hops(self, future):
        asyncio.ensure_future(self._ping_collector(self._monfut))
        while not self._done:
            t = await self._ping('149.43.80.25')

            await asyncio.sleep(self._mon_interval)

            cpuidle = float(self._monitors['cpu'].results.compute_stat(mean, 'cpuidle', 2))
            if cpuidle < 10:
                self._mon_interval *= 2.0
            elif cpuidle > 80:
                self._mon_interval /= 2.0

            for m in self._monitors.values():
                m.set_interval(self._mon_interval)

    def run(self, commandline):
        self._ifinfo = get_interface_info(self._ports.keys())
        self._routes = get_routes(self._ifinfo)

        for intf in self._ifinfo:
            print("{} -> {}".format(intf, self._ifinfo[intf]))
        for prefix in self._routes:
            print("{} -> {}".format(prefix, self._routes[prefix]))

        # self._prepost_profile()

        self._monfut = asyncio.Future()
        xfut = asyncio.Future()
        asyncio.ensure_future(self._monitor_first_n_hops(xfut))

        self._toolfut = asyncio.Future()
        asyncio.ensure_future(self._run_tool(commandline, self._toolfut))
        self._toolfut.add_done_callback(self._shutdown)
        
        # l = asyncio.get_event_loop()
        # t = l.time()
        # l.call_later(relsec)
        # l.call_at(abssec)

        try:
            self._asyncloop.run_forever()
        finally:
            self._asyncloop.close()

        #if not self._monfut.cancelled():
        #    self._log.info('monfuture result: {!r}'.format(self._monfut.result()))


def main():
    m = MeasurementObserver(True)
    m.add_port('en0', 'icmp or arp')
    m.add_monitor('cpu', SystemObserver(TopCommandParser))
    m.add_monitor('io', SystemObserver(IostatCommandParser))
    m.add_monitor('netstat', SystemObserver(NetstatIfaceStatsCommandParser))
    commandline = "sleep 5"
    m.run(commandline)

if __name__ == '__main__':
    main()

