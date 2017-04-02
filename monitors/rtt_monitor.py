import sys
import asyncio
from time import time
import socket
import logging
import functools
import os
from enum import Enum

from monitor_base import DataSource, SystemObserver, _gamma_observer

from switchyard.lib.userlib import *
from switchyard import pcapffi
from localnet import *


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


class RTTProbeType(Enum):
    HopLimited = 1
    EchoRequestReply = 2


class ICMPHopLimitedRTTSource(DataSource):
    '''
    Monitor RTTs to some number of hops using ICMP echo requests with low
    TTLs.  Uses Switchyard libraries to handle packet construction/emission/reception.
    '''
    def __init__(self, interface, numhops=1, dest="8.8.8.8"):
        DataSource.__init__(self)
        self._dest = dest # by default, direct toward GOOG public DNS anycast
        self._numhops = numhops
        self._icmpseq = 1
        self._arp_cache = read_system_arp_cache()
        self._arp_queue = asyncio.Queue()
        self._icmp_queue = asyncio.Queue()
        self._ports = {}
        if sys.platform == 'linux':
            self._sendports = {}
        self._log = logging.getLogger('mm')
        self._monfut = asyncio.Future()
        self._ifinfo = self._routes = None
        self._icmpident = os.getpid()%65536
        self._seqhash = { ICMPType.EchoRequest: {},
                          ICMPType.TimeExceeded: {} }
        self._beforesend = {}
        asyncio.ensure_future(self._ping_collector(self._monfut))

    def add_port(self, ifname, filterstr=''):
        p = pcapffi.PcapLiveDevice.create(ifname)
        p.snaplen = 128
        p.set_promiscuous(True)
        p.set_timeout(100)

        # choose the "best" timestamp available:
        # highest number up to 3 (don't use unsynced adapter stamps)

        stamptypes = [ t for t in p.list_tstamp_types() if t <= pcapffi.PcapTstampType.Adapter ]
        if len(stamptypes):
            beststamp = max(stamptypes)
            try:
                p.set_tstamp_type(beststamp)
                stval = pcapffi.PcapTstampType(beststamp)
                self._log.info("Set timestamp type to {}".format(stval.name))
            except:
                self._log.warn("Couldn't set timestamp type to the advertised value {}".format(stval.name))

        try:
            p.tstamp_precision = pcapffi.PcapTstampPrecision.Nano
            self._log.info("Using nanosecond timestamp precision.")
        except:
            self._log.info("Using microsecond timestamp precision.")

        w = p.activate()
        if w != 0:
            wval = pcapffi.PcapWarning(w)
            self._log.warn("Warning on activation: {}".format(wval.name))

        p.set_direction(pcapffi.PcapDirection.InOut)
        p.set_filter("icmp or arp")

        self._ports[ifname] = p
        if sys.platform == 'linux':
            # on Linux, create a separate packet/raw socket for sending due to
            # linux-only limitations.  In particular, unlike other platforms (BSDish),
            # we cannoot receive the same packet as sent on a device (and thus get
            # hw timestamps on send).  Thus, we create a separate device for sending
            # and can receive both outgoing (that we send) and incoming packets.
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, EtherType.IPv4)
            s.bind((ifname, EtherType.IPv4))  
            self._sendports[ifname] = s

        asyncio.get_event_loop().add_reader(p.fd, 
            functools.partial(self._packet_arrival_callback, pcapdev=p))

    def __call__(self):
        asyncio.ensure_future(self._emiticmp(self._dest))            

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
                self._arp_queue.put_nowait((a.senderhwaddr, a.senderprotoaddr))
            elif pkt.has_header(ICMP):
                #self._log.debug("Got something ICMP")
                if (pkt[ICMP].icmptype == ICMPType.EchoReply and \
                    pkt[ICMP].icmpdata.identifier == self._icmpident):
                    seq = pkt[ICMP].icmpdata.sequence
                    self._log.debug("Got ICMP echo reply on {} at {}: {}".format(name, ts, pkt))
                    self._icmp_queue.put_nowait((ts,seq,pkt[IPv4].src,pkt))
                elif pkt[ICMP].icmptype == ICMPType.TimeExceeded:
                    p = Packet(pkt[ICMP].icmpdata.data, first_header=IPv4) 
                    if p[ICMP].icmpdata.identifier == self._icmpident:
                        self._log.debug("Got ICMP timeexc on {} at {}: {}".format(name, ts, pkt))
                        #self._log.debug("orig pkt: {}".format(p))
                        seq = p[ICMP].icmpdata.sequence
                        ident = p[ICMP].icmpdata.identifier
                        self._icmp_queue.put_nowait((ts,seq,pkt[IPv4].src,pkt))
                elif pkt[ICMP].icmptype == ICMPType.EchoRequest and \
                    pkt[ICMP].icmpdata.identifier == self._icmpident:
                        self._log.debug("Got our echo request on {} at {}: {}".format(name, ts, pkt))
                        seq = pkt[ICMP].icmpdata.sequence
                        self._icmp_queue.put_nowait((ts,seq,pkt[IPv4].src,pkt))
            else:
                self._log.debug("Ignoring packet from {}: {}".format(name, pkt))

    def _send_packet(self, intf, pkt):
        if sys.platform == 'linux':
            dev = self._sendports[intf]
            dev.send(pkt.to_bytes()) 
        else:
            dev = self._ports[intf]
            dev.send_packet(pkt.to_bytes()) 

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
            self._arp_cache[str(ipaddr)] = ethaddr
            if ipaddr == dst:
                break
        return ethaddr

    async def _emiticmp(self, dst):
        try:
            nh = self._routes[dst]
        except KeyError:
            raise RuntimeException("No route to destination {} for network monitoring".format(dst))

        if str(nh.nexthop) == '0.0.0.0': # address on same subnet
            nexthopaddr = dest
        else:
            nexthopaddr = nh.nexthop

        try:
            ethaddr = await self._do_arp(str(nexthopaddr), nh.interface)
        except asyncio.CancelledError:
            return

        thisintf = self._ifinfo[nh.interface]
        pkt = Ethernet(src=thisintf.ethsrc, dst=ethaddr) + \
            IPv4(src=thisintf.ipsrc.ip, dst=dst, protocol=IPProtocol.ICMP,
                ttl=self._numhops) + \
            ICMP(icmptype=ICMPType.EchoRequest,
                identifier=self._icmpident,
                sequence=self._icmpseq)
        self._log.debug("Emitting icmp echo request: {}".format(pkt))
        seq = self._icmpseq
        self._icmpseq += 1
        if self._icmpseq == 65536:
            self._icmpseq = 1
        self._beforesend[seq] = time()
        self._send_packet(nh.interface, pkt)

    async def _ping_collector(self, fut):
        def store_result(seq, beforesend, pcapsend, pcaprecv):
            icmprtt = pcaprecv - pcapsend
            self._add_result({'icmprtt':icmprtt,'seq':seq,'recv':pcaprecv,
                'usersend':beforesend, 'pcapsend':pcapsend})
            self._num_probes += 1


        A = ICMPType.EchoRequest
        B = ICMPType.TimeExceeded
        seqhash = self._seqhash
        echo = self._seqhash[A]
        exc = self._seqhash[B]
        self._num_probes = 0

        while not self._done:
            try:
                ts,seq,src,pkt = await self._icmp_queue.get()
            except asyncio.CancelledError:
                break

            xhash = seqhash[pkt[ICMP].icmptype]
            xhash[seq] = ts

        for seq in sorted(self._beforesend.keys()):
            store_result(seq, self._beforesend[seq], 
                echo.get(seq, float('inf')), exc.get(seq, float('inf')))

        fut.set_result(self._num_probes)

    def setup(self, metamaster, resultscontainer):
        self._ifinfo = get_interface_info(self._ports.keys())
        self._routes = get_routes(self._ifinfo)
        self._add_result = resultscontainer.add_result
        self._add_metadata = metamaster.add_metadata

        # debugging: dump out all interface and route info
        # for intf in self._ifinfo:
        #     print("{} -> {}".format(intf, self._ifinfo[intf]))
        # for prefix in self._routes:
        #     print("{} -> {}".format(prefix, self._routes[prefix]))

    def cleanup(self):
        # close pcap devices and get stats from them
        pcapstats = {}
        for ifname,pcapdev in self._ports.items():
            s = pcapdev.stats()
            pcapstats[ifname] = {'recv':s.ps_recv,
                'pcapdrop':s.ps_drop, 'ifdrop':s.ps_ifdrop}
            self._log.info("Closing {}: {}".format(ifname, s))
            pcapdev.close()
        if sys.platform == 'linux':
            for ifname,rawsock in self._sendports.items():
                self._log.info("Closing rawsock for sending on {}".format(ifname, s))
                rawsock.close()

        self._add_metadata('libpcap_stats', pcapstats)
        self._add_metadata('icmpsource_config', {
                'hops_monitored': self._numhops,
                'total_probes_emitted': self._num_probes,
            })


def create(config):
    i = ICMPHopLimitedRTTSource()
    if not 'interface' in config:
        raise RuntimeError("RTT monitor must have interface configured for it")
    i.add_port(config.pop('interface'), 'icmp or arp')
    return SystemObserver(i, _gamma_observer(configdict.get('proberate', 1)))
