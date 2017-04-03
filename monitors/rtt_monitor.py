import sys
import asyncio
from time import time
import socket
import logging
import functools
import os
from enum import IntEnum

from psutil import net_if_stats

from monitor_base import DataSource, SystemObserver, _gamma_observer, ConfigurationError

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


_protomap = {
    'icmp': (IPProtocol.ICMP,ICMP),
    'tcp': (IPProtocol.TCP,TCP),
    'udp': (IPProtocol.UDP,UDP),
}


class ProbeDirection(IntEnum):
    Outgoing = 0
    Incoming = 1


class RTTProbeSource(DataSource):
    '''
    Monitor RTTs to some number of hops using ICMP echo requests with low
    TTLs.  Uses Switchyard libraries to handle packet construction/emission/reception.
    '''
    def __init__(self, interface, probetype, proto, samples,
        maxttl, allhops, dest):
        DataSource.__init__(self)
        self._interface = interface
        self._probetype = probetype

        self._probeprotostr = proto
        self._probeproto = _protomap[proto][0]
        self._probeprotocls = _protomap[proto][1]
        self._samples_per_probe = samples
        self._maxttl = maxttl  # only meaningful for hop-limited probes
        self._probe_all_hops = allhops # only meaningful for hop-limited probes
        self._dest = dest 
        self._destport = 44444 # for UDP and TCP probes

        self._probeseq = 1

        self._arp_cache = read_system_arp_cache()
        self._arp_queue = asyncio.Queue()
        self._probe_queue = asyncio.Queue()

        if sys.platform == 'linux':
            self._sendsock = None
        self._log = logging.getLogger('mm')
        self._ifinfo = None

        self._pktident = os.getpid()%65536

        self._seqhash = {
            ProbeDirection.Incoming: {},
            ProbeDirection.Outgoing: {},
        }

        if self._probetype != 'hoplimited':
            self._maxttl = 64

        self._lookup_nexthop()
        self._construct_packet_template()

        self._beforesend = {}

        if self._probeprotostr == 'icmp':
            filt = '(icmp[icmptype] == icmp-echo or icmp[icmptype] == icmp-echoreply or icmp[icmptype] == icmp-timxceed) or arp'
        else:
            filt = 'icmp[icmptype]==icmp-timxceed or arp or dst port {}'.format(self._destport)
        self._setup_port(interface, filt)

        self._monfut = asyncio.Future()
        asyncio.ensure_future(self._ping_collector(self._monfut))

    def _setup_port(self, ifname, filterstr=''):
        p = pcapffi.PcapLiveDevice.create(ifname)
        p.snaplen = 256
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

        self._pcap = p
        if sys.platform == 'linux':
            # on Linux, create a separate packet/raw socket for sending due to
            # linux-only limitations.  In particular, unlike other platforms (BSDish),
            # we cannoot receive the same packet as sent on a device (and thus get
            # hw timestamps on send).  Thus, we create a separate device for sending
            # and can receive both outgoing (that we send) and incoming packets.
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, EtherType.IPv4)
            s.bind((ifname, EtherType.IPv4))  
            self._sendsock = s

        asyncio.get_event_loop().add_reader(p.fd, self._packet_arrival_callback)

    def _lookup_nexthop(self):
        self._ifinfo = get_interface_info(self._interface)
        routes = get_routes(self._ifinfo)
        # debugging: dump out all interface and route info
        # for intf in self._ifinfo:
        #     print("{} -> {}".format(intf, self._ifinfo[intf]))
        # for prefix in routes:
        #     print("{} -> {}".format(prefix, routes[prefix]))
        try:
            nh = routes[self._dest]
        except KeyError:
            raise RuntimeException("No route to destination {} for network monitoring".format(self._dest))
        if str(nh.nexthop) == '0.0.0.0': # address on same subnet
            self._nexthopip = self._dest
        else:
            self._nexthopip = nh.nexthop

    def __call__(self):
        asyncio.ensure_future(self._emitprobe(self._dest))            

    def _packet_arrival_callback(self):
        while True:
            p = self._pcap.recv_packet_or_none()
            if p is None:
                break

            name = self._pcap.name
            pkt = decode_packet(self._pcap.dlt, p.raw)
            ts = p.timestamp
            ptup = (name,ts,pkt)

            if pkt.has_header(Arp) and \
              pkt[Arp].operation == ArpOperation.Reply: 
                a = pkt[Arp]
                self._arp_queue.put_nowait((a.senderhwaddr, a.senderprotoaddr))
            elif pkt.has_header(ICMP):
                if (pkt[ICMP].icmptype in (ICMPType.EchoReply,ICMPType.EchoRequest) and \
                    pkt[ICMP].icmpdata.identifier == self._pktident):
                    seq = pkt[ICMP].icmpdata.sequence
                    direction = ProbeDirection.Outgoing 
                    sample = 0 # FIXME
                    if pkt[ICMP].icmptype == ICMPType.EchoReply:
                        direction = ProbeDirection.Incoming
                    self._probe_queue.put_nowait((ts,seq,sample,pkt[IPv4].src,pkt[IPv4].ttl,direction))

                    # FIXME: outgoing echo request needs to include sample, origttl in
                    # the payload

                elif pkt[ICMP].icmptype == ICMPType.TimeExceeded:
                    p = Packet(pkt[ICMP].icmpdata.data, first_header=IPv4) 
                    if p.has_header(self._probeprotocls):
                        seq, ident = self._decode_packet_carcass(p)
                        if ident == self._pktident:
                            origipid = p[IPv4].ipid
                            origttl = origipid & 0xff
                            sample = origipid >> 8
                            self._probe_queue.put_nowait((ts,seq,sample,pkt[IPv4].src,origttl,ProbeDirection.Incoming))

            # identify our outgoing TCP or UDP probe packet.  ICMP is caught
            # in prevous elif
            elif pkt.has_header(self._probeprotocls): 
                seq,ident = self._decode_packet_carcass(pkt)
                if ident == self._pktident:
                    ipid = pkt[IPv4].ipid
                    origttl = ipid & 0xff
                    sample = ipid >> 8
                    self._probe_queue.put_nowait((ts,seq,sample,pkt[IPv4].src,origttl,ProbeDirection.Outgoing))

    def _decode_packet_carcass_icmp(self, p):
        seq = p[ICMP].icmpdata.sequence
        ident = p[ICMP].icmpdata.identifier
        return seq, ident

    def _decode_packet_carcass_tcp(self, p):
        pass

    def _decode_packet_carcass_udp(self, p):
        pass

    def _send_packet(self, intf, pkt):
        if sys.platform == 'linux':
            self._sendsock.send(pkt.to_bytes())
        else:
            self._pcap.send_packet(pkt.to_bytes()) 

    async def _do_arp(self, ethsrc, ipsrc, dst, intf):
        if dst in self._arp_cache:
            return self._arp_cache[dst]
        arpreq = create_ip_arp_request(ethsrc, ipsrc, dst)
        fareth = "00:00:00:00:00:00"
        self._send_packet(intf, arpreq)
        while True:
            try:
                ethaddr,ipaddr = await self._arp_queue.get()
            except asyncio.CancelledError:
                break
            self._arp_cache[str(ipaddr)] = ethaddr
            if ipaddr == dst:
                break
        return ethaddr

    def _construct_packet_template(self):
        '''
        Construct a packet template for sending.  Things yet to be filled in:
            - Ethernet.dst
            - IPv4.ttl (possibly)
            - Probe sequence
            - Probe sample #
            ... done in _fill_in_pkt_details
        '''
        thisintf = self._ifinfo[self._interface]
        self._pkttemplate = \
            Ethernet(src=thisintf.ethsrc) + \
            IPv4(src=thisintf.ipsrc.ip, dst=self._dest, protocol=self._probeproto, 
                ttl=self._maxttl)

        if self._probeproto == IPProtocol.ICMP:
            l4 = ICMP(icmptype=ICMPType.EchoRequest,
                      identifier=self._pktident)
        elif self._probeproto == IPProtocol.TCP:
            l4 = TCP(src=ident, dst=self._dstport, window=228)
            l4.SYN = 1
        elif self._probeproto == IPProtocol.UDP:
            l4 = UDP(src=ident, dst=self._dstport)
        self._pkttemplate += l4

    def _fill_in_pkt_details_icmp(self, ethdst, ttl, seq, sample):
        self._pkttemplate[Ethernet].dst = ethdst
        self._pkttemplate[IPv4].ttl = ttl
        self._pkttemplate[IPv4].ipid = sample << 8 | ttl
        self._pkttemplate[ICMP].icmpdata.sequence = seq

    def _fill_in_pkt_details_tcp(self, ethdst, ttl, seq, sample):
        self._pkttemplate[Ethernet].dst = ethdst
        self._pkttemplate[IPv4].ttl = ttl
        self._pkttemplate[IPv4].ipid = sample << 8 | ttl
        self._pkttemplate[TCP].seq = seq

    def _fill_in_pkt_details_udp(self, ethdst, ttl, seq, sample):
        self._pkttemplate[Ethernet].dst = ethdst
        self._pkttemplate[IPv4].ttl = ttl
        self._pkttemplate[IPv4].ipid = sample << 8 | ttl
        ipid = sequence # FIXME

    async def _emitprobe(self, dst):
        thisintf = self._ifinfo[self._interface]

        try:
            dsteth = await self._do_arp(thisintf.ethsrc, thisintf.ipsrc.ip, 
                self._nexthopip, self._interface)
        except asyncio.CancelledError:
            return

        # FIXME: multiple TTLs (for along a path)
        # FIXME: multiple samples per sequence

        seq = self._probeseq
        self._fill_in_pkt_details(dsteth, self._maxttl, seq, 0)
        self._probeseq += 1
        if self._probeseq == 65536:
            self._probeseq = 1

        self._beforesend[seq] = time()
        self._send_packet(self._interface, self._pkttemplate)

    async def _ping_collector(self, fut):
        def store_result(seq, beforesend, pcapsend, pcaprecv):
            icmprtt = pcaprecv - pcapsend
            userrtt = pcaprecv - beforesend
            self._add_result({'pcaprtt':icmprtt,'seq':seq,'recv':pcaprecv,
                'usersend':beforesend, 'pcapsend':pcapsend, 'userrtt':userrtt})
            self._num_probes += 1

        seqhash = self._seqhash
        outgoing = self._seqhash[ProbeDirection.Outgoing]
        incoming = self._seqhash[ProbeDirection.Incoming]
        self._num_probes = 0

        while not self._done:
            try:
                ts,seq,sample,src,origttl,direction = await self._probe_queue.get()
            except asyncio.CancelledError:
                break

            xhash = seqhash[direction]
            xhash[seq] = ts

        for seq in sorted(self._beforesend.keys()):
            store_result(seq, self._beforesend[seq], 
                outgoing.get(seq, float('inf')), incoming.get(seq, float('inf')))

        fut.set_result(self._num_probes)

    def setup(self, metamaster, resultscontainer):
        self._add_result = resultscontainer.add_result
        self._add_metadata = metamaster.add_metadata

        # setup fill-in and decode pkt handlers
        if self._probeproto == IPProtocol.ICMP:
            self._decode_packet_carcass = self._decode_packet_carcass_icmp
            self._fill_in_pkt_details = self._fill_in_pkt_details_icmp
        elif self._probeproto == IPProtocol.TCP:
            self._decode_packet_carcass = self._decode_packet_carcass_tcp
            self._fill_in_pkt_details = self._fill_in_pkt_details_tcp
        if self._probeproto == IPProtocol.UDP:
            self._decode_packet_carcass = self._decode_packet_carcass_udp
            self._fill_in_pkt_details = self._fill_in_pkt_details_udp

    def cleanup(self):
        # close pcap devices and get stats from them
        pcapstats = {}
        s = self._pcap.stats()
        stats = {'recv':s.ps_recv, 'pcapdrop':s.ps_drop, 'ifdrop':s.ps_ifdrop}
        self._add_metadata('libpcap_stats_{}'.format(self._interface), stats)
        self._log.info("Closing {}: {}".format(self._interface, s))
        self._pcap.close()
        
        if sys.platform == 'linux':
            self._log.info("Closing rawsock for sending on {}".format(self._interface))
            self._sendsock.close()

        dconfig = { 'protocol':self._probeprotostr,
                    'probetype':self._probetype,
                    'samples_per_probe':self._samples_per_probe,
                    'dest':self._dest,
                    'total_probes_emitted': self._num_probes }
        if self._probetype == 'hoplimited':
            dconfig['maxttl'] = self._maxttl
            dconfig['probe_all_hops'] = self._probe_all_hops
        self._add_metadata('rttprobe_config', dconfig)


def create(config):
    '''
    Configuration options:
        interface=interface_name
        dest=probe_destination (IP address or name)
        rate=probe_rate (average probes/sec; probes are emitted according to an erlang distribuion
        type=(ping|hoplimited) #
        proto=(icmp|tcp|udp) # ping type implies icmp; default for hoplimited is icmp
        samples=1 # number of probe samples per sequence number (default = 1)
        maxttl=1
        allhops=True
    '''
    if not 'interface' in config:
        raise ConfigurationError("Missing 'interface' config item for RTT monitor.")
    interface = config.pop('interface')

    validiface = list(net_if_stats().keys())
    if interface not in net_if_stats().keys():
        raise ConfigurationError("Invalid interface name {} for RTT monitor (valid names: {})".format(interface, ','.join(validiface)))

    try:
        dest = socket.gethostbyname(config.pop('dest', '8.8.8.8'))
    except:
        raise ConfigurationError("Bad destination {} (lookup failed)".format(dest))

    probetype = config.pop('type', 'hoplimited')
    if probetype not in ['ping','hoplimited']:
        raise ConfigurationError("Bad RTT monitor probe type {}.  Must be one of 'ping' or 'hoplimited' (default='hoplimited')".format(probetype))

    if probetype == 'hoplimited':
        protostr = config.pop('proto', 'icmp')
        if protostr not in ['icmp','udp','tcp']:
            raise ConfigurationError("Bad hoplimited protocol {}.  Must be one of 'icmp', 'udp', or 'tcp' (default=icmp)".format(protostr))
    else:
        protostr = 'icmp'

    samples = int(config.pop('samples', 1))
    maxttl = int(config.pop('maxttl', 1))
    allhops = bool(config.pop('allhops', True))

    rate = float(config.pop('rate', 1))
    if config:
        raise ConfigurationError("Unused configuration items for RTT monitor: {}".format(config))
    prober = RTTProbeSource(interface, probetype, protostr, samples, 
        maxttl, allhops, dest)
    return SystemObserver(prober, _gamma_observer(rate))
