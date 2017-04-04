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


# destination port for TCP and UDP probes
DESTPORT = 44444

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

class ProbeDirection(IntEnum):
    Outgoing = 0
    Incoming = 1


class ArpCache(object):
    TIMEOUT = 600

    def __init__(self):
        self._cache = {}
        for ipaddr,ethaddr in read_system_arp_cache().items():
            self.update(ipaddr, ethaddr)

    def lookup(self, ipaddr):
        if ipaddr in self._cache:
            ethaddr, ts = self._cache[ipaddr]
            tdiff = time() - ts
            if tdiff < ArpCache.TIMEOUT:
                return ethaddr
        return None

    def update(self, ipaddr, ethaddr):
        self._cache[ipaddr] = (ethaddr, time())


class ProbeHelper(object):
    @staticmethod
    def reconstruct_carcass(raw):
        p = Packet()
        ip = IPv4()
        rawremain = ip.from_bytes(raw)
        p += ip
        return p,rawremain

    @staticmethod
    def make_packet_template(ethsrc, ipsrc, ipdst, proto, maxttl):
        p = Ethernet(src=ethsrc) + \
            IPv4(src=ipsrc, dst=ipdst, protocol=proto, ttl=maxttl)
        return p

    @staticmethod
    def fill_in(p, ethdst, ttl):
        p[Ethernet].dst = ethdst
        p[IPv4].ttl = ttl


class ICMPProbeHelper(ProbeHelper):
    '''
    identifier: ICMP echo ident
    sequence: ICMP echo seq
    '''
    name = 'icmp'
    klass = ICMP
    proto = IPProtocol.ICMP
    pcapfilter = '(icmp[icmptype] == icmp-echo or icmp[icmptype] == icmp-echoreply or icmp[icmptype] == icmp-timxceed) or arp'

    @staticmethod
    def reconstruct_carcass(raw):
        p,raw = ProbeHelper.reconstruct_carcass(raw)
        icmp = ICMP()
        icmp.from_bytes(raw)
        p += icmp
        return p

    @staticmethod
    def decode_carcass(p):
        seq = p[ICMP].icmpdata.sequence
        ident = p[ICMP].icmpdata.identifier
        return seq, ident

    @staticmethod
    def make_packet_template(ethsrc, ipsrc, ipdst, proto, maxttl, ident, dport=44444):
        p = ProbeHelper.make_packet_template(ethsrc, ipsrc, ipdst, proto, maxttl)
        p += ICMP(icmptype=ICMPType.EchoRequest, identifier=ident)
        return p

    @staticmethod
    def fill_in(p, ethdst, ttl, seq):
        ProbeHelper.fill_in(p, ethdst, ttl)
        p[ICMP].icmpdata.sequence = seq


class TCPProbeHelper(ProbeHelper):
    '''
    identifier: TCP source port
    sequence: TCP sequence (it is within the first 8 bytes of TCP header)
    '''
    name = 'tcp'
    klass = TCP
    proto = IPProtocol.TCP
    pcapfilter = 'icmp[icmptype]==icmp-timxceed or arp or dst port {}'.format(DESTPORT)

    @staticmethod
    def reconstruct_carcass(raw):
        p,raw = ProbeHelper.reconstruct_carcass(raw)
        tcp = TCP()
        newraw = raw + (20 - len(raw))*b'\x00'
        tcp.from_bytes(newraw)
        p += tcp
        return p

    @staticmethod
    def decode_carcass(p):
        seq = p[TCP].seq
        ident = p[TCP].src
        return seq, ident

    @staticmethod
    def make_packet_template(ethsrc, ipsrc, ipdst, proto, maxttl, ident, dport=DESTPORT):
        p = ProbeHelper.make_packet_template(ethsrc, ipsrc, ipdst, proto, maxttl)
        p += TCP(src=ident, dst=dport, window=228)
        p[TCP].SYN = 1
        return p

    @staticmethod
    def fill_in(p, ethdst, ttl, seq):
        ProbeHelper.fill_in(p, ethdst, ttl)
        p[TCP].seq = seq


class UDPProbeHelper(ProbeHelper):
    '''
    identifier: UDP source port
    sequence: IP id
    '''
    name = 'udp'
    klass = UDP
    proto = IPProtocol.UDP
    pcapfilter = 'icmp[icmptype]==icmp-timxceed or arp or dst port {}'.format(DESTPORT)

    @staticmethod
    def reconstruct_carcass(raw):
        p,raw = ProbeHelper.reconstruct_carcass(raw)
        udp = UDP()
        udp.from_bytes(raw)
        p += udp
        return p

    @staticmethod
    def decode_carcass(p):
        seq = p[IPv4].ipid
        ident = p[UDP].src
        return seq, ident

    @staticmethod
    def make_packet_template(ethsrc, ipsrc, ipdst, proto, maxttl, ident, dport=DESTPORT):
        p = ProbeHelper.make_packet_template(ethsrc, ipsrc, ipdst, proto, maxttl)
        p += UDP(src=ident, dst=dport)
        return p

    @staticmethod
    def fill_in(p, ethdst, ttl, seq):
        ProbeHelper.fill_in(p, ethdst, ttl)
        p[IPv4].ipid = seq


_protomap = {
    'icmp': ICMPProbeHelper,
    'tcp': TCPProbeHelper,
    'udp': UDPProbeHelper,
}


# FIXME: doesn't yet handle sequence wrap when compiling results


class RTTProbeSource(DataSource):
    '''
    Monitor RTTs to some number of hops using ICMP echo requests with low
    TTLs.  Uses Switchyard libraries to handle packet construction/emission/reception.
    '''
    def __init__(self, interface, probetype, proto, maxttl, allhops, dest):
        DataSource.__init__(self)
        self._interface = interface
        self._ifinfo = get_interface_info(self._interface)
        self._probetype = probetype
        self._probehelper = _protomap[proto]

        if self._probetype == 'ping':
            self._maxttl = 64
            self._probe_all_hops = False
        elif self._probetype == 'hoplimited':
            self._maxttl = maxttl  # only meaningful for hop-limited probes
            self._probe_all_hops = allhops # only meaningful for hop-limited probes

        self._dest = IPv4Address(dest)
        self._nexthopip = self._lookup_nexthop() 

        self._probeseq = 1
        self._probewrap = 65536
        self._num_probes_sent = self._num_probes_recv = 0

        self._arp_cache = ArpCache()
        self._arp_queue = asyncio.Queue()
        self._probe_queue = asyncio.Queue()

        if sys.platform == 'linux':
            self._sendsock = None
        self._log = logging.getLogger('mm')

        self._pktident = os.getpid()% 65536

        self._usersend = {}
        self._seqhash = {
            ProbeDirection.Incoming: {},
            ProbeDirection.Outgoing: {},
        }

        ifinfo = self._ifinfo[self._interface]

        self._pkttemplate = self._probehelper.make_packet_template(ifinfo.ethsrc, 
            ifinfo.ipsrc.ip, self._dest, self._probehelper.proto, 
            self._maxttl, self._pktident, dport=DESTPORT)

        self._setup_port(interface, self._probehelper.pcapfilter)

        self._monfut = asyncio.Future()
        asyncio.ensure_future(self._ping_collector(self._monfut))

    def _setup_port(self, ifname, filterstr):
        p = pcapffi.PcapLiveDevice.create(ifname)
        p.snaplen = 256
        p.set_promiscuous(True)
        p.set_timeout(10)
        #p.set_immediate_mode(True)

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
        p.set_filter(filterstr)

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
            return self._dest
        else:
            return nh.nexthop

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
                self._log.debug("Got ICMP: {}".format(pkt))
                if (pkt[ICMP].icmptype in (ICMPType.EchoReply,ICMPType.EchoRequest) and \
                    pkt[ICMP].icmpdata.identifier == self._pktident):
                    seq = pkt[ICMP].icmpdata.sequence
                    direction = ProbeDirection.Outgoing 
                    if pkt[ICMP].icmptype == ICMPType.EchoReply:
                        direction = ProbeDirection.Incoming
                    self._probe_queue.put_nowait((ts,seq,pkt[IPv4].src,pkt[IPv4].ttl,direction))
                elif pkt[ICMP].icmptype == ICMPType.TimeExceeded:
                    p = self._probehelper.reconstruct_carcass(pkt[ICMP].icmpdata.data)
                    origttl = self._infer_orig_ttl(pkt[IPv4].ttl)
                    self._log.debug("Packet carcass: {}".format(p))
                    if p.has_header(self._probehelper.klass):
                        # ttl stuffed into ipid of previously sent pkt is unreliable
                        seq, ident = self._probehelper.decode_carcass(p)
                        if ident == self._pktident:
                            self._probe_queue.put_nowait((ts,seq,pkt[IPv4].src,origttl,ProbeDirection.Incoming))

            # identify our outgoing TCP or UDP probe packet.  ICMP is caught
            # in prevous elif
            elif pkt.has_header(self._probehelper.klass): 
                seq,ident = self._probehelper.decode_carcass(pkt)
                origttl = pkt[IPv4].ttl
                if ident == self._pktident:
                    self._probe_queue.put_nowait((ts,seq,pkt[IPv4].src,origttl,ProbeDirection.Outgoing))

    @staticmethod
    def _infer_orig_ttl(recvttl):
        if recvttl > 128:
            return 255-recvttl+1
        elif recvttl > 64:
            return 128-recvttl+1
        elif recvttl > 32:
            return 64-recvttl+1
        return 32-recvttl+1

    def _send_packet(self, intf, pkt):
        self._log.debug("Sending on {}: {}".format(intf, pkt))
        if sys.platform == 'linux':
            self._sendsock.send(pkt.to_bytes())
        else:
            self._pcap.send_packet(pkt.to_bytes()) 

    async def _do_arp(self, ethsrc, ipsrc, dst, intf):
        ethdst = self._arp_cache.lookup(dst)
        if ethdst is not None:
            self._log.debug("ARP cache hit")
            return ethdst

        self._log.debug("ARP cache miss; sending req for {} ({})".format(dst))
        last_send = 0
        left_to_send = 5 # 5 attempts, wait 1 sec each
        ethdst = None

        while left_to_send > 0:
            now = time()
            if now - last_send > 1:
                self._send_packet(intf, 
                    create_ip_arp_request(ethsrc, ipsrc, dst))
                last_send = now
                left_to_send -= 1

            try:
                ethaddr,ipaddr = await self._arp_queue.get()
            except asyncio.CancelledError:
                break

            self._arp_cache.update(IPv4Address(ipaddr), EthAddr(ethaddr))

            if ipaddr == dst:
                ethdst = ethaddr
                break

        return ethdst

    async def _emitprobe(self, dst):
        thisintf = self._ifinfo[self._interface]
        self._num_probes_sent += 1

        try:
            ethdst = await self._do_arp(thisintf.ethsrc, thisintf.ipsrc.ip, 
                self._nexthopip, self._interface)
        except asyncio.CancelledError:
            return

        if ethdst is None:
            return

        seq = self._probeseq

        start_ttl = self._maxttl
        end_ttl = start_ttl - 1
        if self._probe_all_hops:
            end_ttl = 0

        for ttl in range(start_ttl, end_ttl, -1):
            self._probehelper.fill_in(self._pkttemplate, ethdst, ttl, seq)
            self._send_packet(self._interface, self._pkttemplate)
            self._usersend[(seq,ttl)] = time() 

        self._probeseq += 1
        if self._probeseq == self._probewrap:
            self._probeseq = 1

    async def _ping_collector(self, fut):
        def store_result(seq, origttl, usersend, pcapsend, pcaprecv):
            pcaprtt = pcaprecv - pcapsend
            result = {'rtt':pcaprtt, 'recv':pcaprecv, 
                      'send':pcapsend,
                      'origttl':origttl, 'seq':seq }
            self._add_result(result)

        seqhash = self._seqhash
        outgoing = self._seqhash[ProbeDirection.Outgoing]
        incoming = self._seqhash[ProbeDirection.Incoming]

        while not self._done:
            try:
                ts,seq,src,origttl,direction = await self._probe_queue.get()
            except asyncio.CancelledError:
                break

            self._log.debug("Got seq {} from {} ottl {} direction {} at {}".format(
                seq, src, origttl, direction.name, ts))
            if direction == ProbeDirection.Incoming:
                self._num_probes_recv += 1

            xhash = seqhash[direction]
            xhash[(seq,origttl)] = ts

        for seq in sorted(self._usersend.keys()):
            xseq, origttl = seq
            store_result(xseq, origttl, self._usersend[seq],
                              outgoing.get(seq, float('inf')), 
                              incoming.get(seq, float('inf')))

        fut.set_result(self._num_probes_sent)

    def setup(self, metamaster, resultscontainer):
        self._add_result = resultscontainer.add_result
        self._add_metadata = metamaster.add_metadata

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

        dconfig = { 'protocol':self._probehelper.name,
                    'probetype':self._probetype,
                    'dest':str(self._dest),
                    'total_probes_emitted': self._num_probes_sent,
                    'total_probes_received': self._num_probes_recv }
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

    maxttl = int(config.pop('maxttl', 1))
    maxttl = max(maxttl, 1) 
    allhops = bool(config.pop('allhops', True))

    rate = float(config.pop('rate', 1))
    if config:
        raise ConfigurationError("Unused configuration items for RTT monitor: {}".format(config))
    prober = RTTProbeSource(interface, probetype, protostr, 
        maxttl, allhops, dest)
    return SystemObserver(prober, _gamma_observer(rate))