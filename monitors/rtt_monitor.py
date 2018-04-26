import sys
import asyncio
from time import time
import socket
import logging
import functools
import os
from enum import IntEnum

from psutil import net_if_stats, pid_exists

from monitor_base import DataSource, SystemObserver, ResultsContainer, \
    _gamma_observer, ConfigurationError

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
    def make_packet_template(ethsrc, ipsrc, ipdst, proto, maxttl, constflow, dport=44444):
        p = ProbeHelper.make_packet_template(ethsrc, ipsrc, ipdst, proto, maxttl)
        p += ICMP(icmptype=ICMPType.EchoRequest)
        if constflow:
            p[ICMP].icmpdata.data = b'\x00\x00'
        return p

    @staticmethod
    def fill_in(p, ethdst, ttl, ident, seq, constflow):
        ProbeHelper.fill_in(p, ethdst, ttl)
        p[ICMP].icmpdata.sequence = seq
        p[ICMP].icmpdata.identifier = ident
        if constflow:
            x = 65535-(seq%65535) 
            p[ICMP].icmpdata.data = bytes((x>>8, x&0xff))


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
    def make_packet_template(ethsrc, ipsrc, ipdst, proto, maxttl, constflow, dport=DESTPORT):
        p = ProbeHelper.make_packet_template(ethsrc, ipsrc, ipdst, proto, maxttl)
        p += TCP(dst=dport, window=228)
        p[TCP].SYN = 1
        return p

    @staticmethod
    def fill_in(p, ethdst, ttl, ident, seq, constflow):
        ProbeHelper.fill_in(p, ethdst, ttl)
        p[TCP].src = ident
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
        ident = p[UDP].src
        seq = p[UDP].checksum
        return seq, ident

    @staticmethod
    def make_packet_template(ethsrc, ipsrc, ipdst, proto, maxttl, constflow, dport=DESTPORT):
        p = ProbeHelper.make_packet_template(ethsrc, ipsrc, ipdst, proto, maxttl)
        p += UDP(dst=dport)
        p += RawPacketContents(b'\x00\x00')
        return p

    @staticmethod
    def fill_in(p, ethdst, ttl, ident, seq, constflow):
        ProbeHelper.fill_in(p, ethdst, ttl)
        p[UDP].src = ident 
        p[IPv4].ipid = 0
        p[-1] = RawPacketContents(b'\x00\x00')
        p.to_bytes() # force csum computation
        xtra = (p[UDP].checksum - seq) % 65535
        bx = bytes([ xtra>>8, xtra&0xff ])
        p[-1] = RawPacketContents(bx)

_protomap = {
    'icmp': ICMPProbeHelper,
    'tcp': TCPProbeHelper,
    'udp': UDPProbeHelper,
}


class ProbeContainer(object):
    '''
    Containers for (1) indication of when a probe was sent from user space
    (2) when probe is seen on pcapdevice (wiresend), and (3) when
    probe response is seen.

    A reference to the "final" results container is referenced here so that
    as probes come in results can be updated.  NB: the mapping between a
    probe container and results object is 1-1.

    A separate container object is created for each probe ident (i.e., each
    separate hop being probed either with ping-style probes or with 
    hop-limited probes).
    '''
    def __init__(self, outttl, results_bucket):
        self._results = results_bucket
        self._usersend = {}
        self._wiresend = {}
        self._wirerecv = {}
        self._outttl = outttl

    def put_user_send(self, seq, timestamp):
        self._usersend[seq] = timestamp

    def put_wire_send(self, seq, timestamp):
        self._wiresend[seq] = timestamp

    def put_wire_recv(self, seq, wirerecvts, recvttl, ipsrc=None):
        if seq in self._wiresend:
            wiresendts = self._wiresend.pop(seq)
            usersendts = self._usersend.pop(seq)
            self._store_result(seq, recvttl, usersendts, wiresendts, wirerecvts, ipsrc)
        else:
            self._wirerecv[seq] = (wirerecvts, recvttl, ipsrc)

    def flush(self):
        xinf = float('inf')
        for seq,usersendts in self._usersend.items():
            wiresend = self._wiresend.pop(seq, xinf)
            wirerecv,recvttl,ipsrc = self._wirerecv.pop(seq, (xinf,0,''))
            self._store_result(seq, recvttl, usersendts, wiresend, wirerecv, ipsrc)

    def _store_result(self, seq, recvttl, usersend, wiresend, wirerecv, ipsrc=None):
        wirertt = wirerecv - wiresend
        result = {'rtt':wirertt, 'wirerecv':wirerecv, 
            'wiresend':wiresend, 'usersend':usersend,
            'recvttl':recvttl, 'seq':seq }
        if ipsrc is not None:
            result['ipsrc'] = str(ipsrc)
        self._results.add_result(result)

    @property
    def results(self):
        return self._results

    @property
    def outgoing_ttl(self):
        return self._outttl


class RTTProbeSource(DataSource):
    '''
    Monitor RTTs to some number of hops using ICMP echo requests with low
    TTLs.  Uses Switchyard libraries to handle packet construction/emission/reception.
    '''
    _IDENTS = set()

    def __init__(self, interface, probetype, proto, maxttl, allhops, dest, constflow):
        DataSource.__init__(self)
        self._interface = interface
        self._ifinfo = get_interface_info(self._interface)
        self._probetype = probetype
        self._probehelper = _protomap[proto]
        self._constflow = constflow

        num_idents_needed = 1
        if self._probetype == 'ping':
            self._maxttl = 64
            self._probe_all_hops = False
        elif self._probetype == 'hoplimited':
            self._maxttl = maxttl  # only meaningful for hop-limited probes
            self._probe_all_hops = allhops # only meaningful for hop-limited probes
            if allhops:
                num_idents_needed = maxttl

        self._dest = IPv4Address(dest)
        self._nexthopip = self._lookup_nexthop() 

        self._name = "rtt_{}_{}_{}".format(self._probetype, self._interface, self._dest)

        self._probeseq = 1
        self._probewrap = 65535
        self._num_probes_sent = self._num_probes_recv = 0

        self._arp_cache = ArpCache()
        self._arp_queue = asyncio.Queue()
        self._probe_queue = asyncio.Queue()

        if sys.platform == 'linux':
            self._sendsock = None
        self._log = logging.getLogger('mm')

        self._pktident = {}
        self._probecontainers = {}
        idstart = os.getpid() % 65536
        xttl = self._maxttl
        while num_idents_needed > 0:
            if not pid_exists(idstart) and idstart not in RTTProbeSource._IDENTS:
                self._pktident[idstart] = xttl
                self._probecontainers[idstart] = ProbeContainer(xttl, ResultsContainer())
                RTTProbeSource._IDENTS.add(idstart)
                num_idents_needed -= 1
                xttl -= 1
            idstart -= 1
            if idstart == 0:
                idstart = 65535
        self._ttltoident = { v:k for k,v in self._pktident.items() }

        ifinfo = self._ifinfo[self._interface]

        self._pkttemplate = self._probehelper.make_packet_template(ifinfo.ethsrc, 
            ifinfo.ipsrc.ip, self._dest, self._probehelper.proto, 
            self._maxttl, self._constflow, dport=DESTPORT)

        self._setup_port(interface, self._probehelper.pcapfilter)

        self._monfut = asyncio.Future()
        asyncio.ensure_future(self._ping_collector(self._monfut))

    @property
    def name(self):
        return self._name

    def _setup_port(self, ifname, filterstr):
        p = pcapffi.PcapLiveDevice.create(ifname)
        p.snaplen = 128
        p.set_promiscuous(True)
        p.set_timeout(10)

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
            p.tstamp_precision = pcapffi.PcapTstampPrecision.Micro
            self._log.info("Using microsecond timestamp precision.")
        except:
            pass

        # api call doesn't exist everywhere; just ignore if we can't do it
        try:
            p.set_immediate_mode(True)
        except:
            pass

        w = p.activate()
        if w != 0:
            wval = pcapffi.PcapWarning(w)
            self._log.warn("Warning on activation: {}".format(wval.name))

        p.set_direction(pcapffi.PcapDirection.InOut)
        p.set_filter(filterstr)

        self._pcap = p
        if sys.platform == 'linux':
            # on Linux, create a separate packet/raw socket for sending due to
            # linux-only limitations.  In particular, unlike other platforms 
            # (BSDish), we cannot receive the same packet as sent on a device 
            # (and thus get hw timestamps on send).  Thus, we create a 
            # separate device for sending and can receive both outgoing (that 
            # we send) and incoming packets.
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

    def _packet_arrival(self, p):
        name = self._pcap.name
        pkt = decode_packet(self._pcap.dlt, p.raw)
        ts = p.timestamp
        ptup = (name,ts,pkt)

        if isinstance(pkt, RawPacketContents):
            return

        if pkt.has_header(Arp) and pkt[Arp].operation == ArpOperation.Reply: 
            a = pkt[Arp]
            self._arp_queue.put_nowait((a.senderhwaddr, a.senderprotoaddr))
            return

        elif pkt.has_header(ICMP):
            if (pkt[ICMP].icmptype in \
                    (ICMPType.EchoReply,ICMPType.EchoRequest) and \
                    pkt[ICMP].icmpdata.identifier in self._pktident):
                seq = pkt[ICMP].icmpdata.sequence
                ident = pkt[ICMP].icmpdata.identifier
                direction = ProbeDirection.Outgoing 
                if pkt[ICMP].icmptype == ICMPType.EchoReply:
                    direction = ProbeDirection.Incoming
                    # ignore Echo Reply if src addr doesn't match 
                    # our intended dest
                    if pkt[IPv4].src != self._dest:
                        return

                received_ttl = pkt[IPv4].ttl
                self._probe_queue.put_nowait((ts,seq,pkt[IPv4].src,ident,received_ttl,direction))
                return
            elif pkt[ICMP].icmptype == ICMPType.TimeExceeded:
                try:
                    p = self._probehelper.reconstruct_carcass(pkt[ICMP].icmpdata.data)
                except:
                    p = None
                if p is not None and p.has_header(self._probehelper.klass):
                    seq, ident = self._probehelper.decode_carcass(p)
                    if ident in self._pktident and p[IPv4].dst == self._dest:
                        received_ttl = pkt[IPv4].ttl
                        self._probe_queue.put_nowait((ts,seq,pkt[IPv4].src,ident,received_ttl,ProbeDirection.Incoming))

        # identify our outgoing TCP or UDP probe packet.  ICMP is caught
        # in prevous elif
        elif pkt.has_header(self._probehelper.klass): 
            seq,ident = self._probehelper.decode_carcass(pkt)
            received_ttl = pkt[IPv4].ttl
            if ident in self._pktident:
                self._probe_queue.put_nowait((ts,seq,pkt[IPv4].src,ident,received_ttl,ProbeDirection.Outgoing))

    def _packet_arrival_callback(self):
        self._pcap.dispatch(self._packet_arrival, -1)

    def _send_packet(self, intf, pkt):
        self._log.debug("Sending on {}: {}".format(intf, pkt))
        if sys.platform == 'linux':
            self._sendsock.send(pkt.to_bytes())
        else:
            self._pcap.send_packet(pkt.to_bytes()) 

    async def _do_arp(self, ethsrc, ipsrc, dst, intf):
        ethdst = self._arp_cache.lookup(dst)
        if ethdst is not None:
            return ethdst

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
            ident = self._ttltoident[ttl]
            self._probehelper.fill_in(self._pkttemplate, ethdst, ttl, ident, seq, self._constflow)
            self._send_packet(self._interface, self._pkttemplate)
            self._num_probes_sent += 1
            self._probecontainers[ident].put_user_send(seq, time())

        self._probeseq += 1
        if self._probeseq == self._probewrap:
            self._probeseq = 1

    async def _ping_collector(self, fut):
        while not self._done:
            try:
                ts,seq,src,ident,recv_ttl,direction = await self._probe_queue.get()
            except asyncio.CancelledError:
                break

            self._log.debug("Got {} seq {} ident {} from {} recvttl {} at {}".format(
                direction.name, seq, ident, src, recv_ttl, ts))
            if direction == ProbeDirection.Incoming:
                # incoming probe response from remote system
                self._num_probes_recv += 1
                self._probecontainers[ident].put_wire_recv(seq, ts, recv_ttl, src)
            else:
                # outgoing probe (we saw our own packet emit)
                self._probecontainers[ident].put_wire_send(seq, ts)

        for container in self._probecontainers.values():
            container.flush()

        fut.set_result(self._num_probes_sent)

    def _get_pcap_stats(self):
        if self._pcap is None:
            return self._pcapstats
        s = self._pcap.stats()
        self._pcapstats = {'recv':s.ps_recv, 'pcapdrop':s.ps_drop, 'ifdrop':s.ps_ifdrop}
        return self._pcapstats
        
    def cleanup(self):
        s = self._get_pcap_stats()
        self._log.info("Closing {}: {}".format(self._interface, s))
        self._pcap.close()
        self._pcap = None
        if sys.platform == 'linux':
            self._log.info("Closing rawsock for sending on {}".format(self._interface))
            self._sendsock.close()

    def metadata(self):
        xmeta = {}
        xmeta['libpcap_stats'] = self._get_pcap_stats()
        dconfig = { 'protocol':self._probehelper.name,
                    'probetype':self._probetype,
                    'dest':str(self._dest),
                    'total_probes_emitted': self._num_probes_sent,
                    'total_probes_received': self._num_probes_recv }
        if self._probetype == 'hoplimited':
            dconfig['maxttl'] = self._maxttl
            dconfig['probe_all_hops'] = self._probe_all_hops
        xmeta['probe_config'] = dconfig

        if self._probetype == 'ping':
            container = list(self._probecontainers.values())[0]
            xmeta['ping'] = container.results.all()
        else:
            for container in self._probecontainers.values():
                xmeta['ttl_{}'.format(container.outgoing_ttl)] = container.results.all()
        return xmeta

    def show_status(self):
        pass


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
        constflow=True
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
        maxttl = int(config.pop('maxttl', 1))
        maxttl = max(maxttl, 1) 
        allhops = bool(config.pop('allhops', True))

        if protostr == 'tcp':
            DESTPORT = 80
    else:
        if 'proto' in config:
            logging.getLogger('mm').warn("Ignoring 'proto' config for 'ping' RTT monitor (must be icmp)")
            config.pop('proto')
        protostr = 'icmp'

        if 'maxttl' in config:
            logging.getLogger('mm').warn("Ignoring 'maxttl' config for 'ping' RTT monitor (pointless)")
            config.pop('maxttl')
        maxttl = 0

        if 'allhops' in config:
            logging.getLogger('mm').warn("Ignoring 'allhops' config for 'ping' RTT monitor (pointless)")
            config.pop('allhops')
        allhops = False

    constflow = int(config.pop('constflow', False))

    rate = float(config.pop('rate', 1))
    if config:
        raise ConfigurationError("Unrecognized configuration items for RTT monitor: {}".format(config))
    prober = RTTProbeSource(interface, probetype, protostr, 
        maxttl, allhops, dest, constflow)
    return SystemObserver(prober, _gamma_observer(rate))
