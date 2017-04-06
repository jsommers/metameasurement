import sys
import asyncio
from time import time
import socket
import logging
import functools
import os
from enum import IntEnum

from psutil import net_if_stats

from monitor_base import DataSource, SystemObserver, ResultsContainer, \
    _gamma_observer, ConfigurationError

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

class ProbeDirection(IntEnum):
    Outgoing = 0
    Incoming = 1


class PcapReceiverSource(DataSource):
    '''
    Just receive data on a pcap device and collect timestamps.
    '''
    def __init__(self, interface, decode):
        DataSource.__init__(self)
        self._interface = interface
        self._results = ResultsContainer()
        self._log = logging.getLogger('mm')

        self._name = "pcaprecv_{}".format(self._interface)
        self._num_recv = 0
        self._do_decode = decode
        xfilter = 'udp or icmp'
        self._setup_port(interface, xfilter)

        self._monfut = asyncio.Future()

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
            p.tstamp_precision = pcapffi.PcapTstampPrecision.Nano
            self._log.info("Using nanosecond timestamp precision.")
        except:
            self._log.info("Using microsecond timestamp precision.")

        if sys.platform == 'linux':
            try:
                p.set_immediate_mode(True)
            except:
                pass

        w = p.activate()
        if w != 0:
            wval = pcapffi.PcapWarning(w)
            self._log.warn("Warning on activation: {}".format(wval.name))

        p.blocking = False
        p.set_direction(pcapffi.PcapDirection.InOut)
        p.set_filter(filterstr)

        self._pcap = p

        asyncio.get_event_loop().add_reader(p.fd, self._packet_arrival_callback)

    def __call__(self):
        '''Don't do anything when we get called!'''
        pass

    def _packet_arrival_callback(self):
        p = self._pcap.recv_packet_or_none()
        if p is None:
            return

        ts = p.timestamp
        if self._do_decode:
            pkt = decode_packet(self._pcap.dlt, p.raw)

        self._results.add_result(ts)
        return

        if pkt.has_header(Arp) and pkt[Arp].operation == ArpOperation.Reply: 
            a = pkt[Arp]
            self._arp_queue.put_nowait((a.senderhwaddr, a.senderprotoaddr))
            return
        elif pkt.has_header(ICMP):
            if (pkt[ICMP].icmptype in \
                    (ICMPType.EchoReply,ICMPType.EchoRequest) and \
                    pkt[ICMP].icmpdata.identifier == self._pktident):
                seq = pkt[ICMP].icmpdata.sequence
                direction = ProbeDirection.Outgoing 
                if pkt[ICMP].icmptype == ICMPType.EchoReply:
                    direction = ProbeDirection.Incoming
                    # ignore Echo Reply if src addr doesn't match 
                    # our intended dest
                    if pkt[IPv4].src != self._dest:
                        return
                self._probe_queue.put_nowait((ts,seq,pkt[IPv4].src,pkt[IPv4].ttl,direction))
                return
            elif pkt[ICMP].icmptype == ICMPType.TimeExceeded:
                p = self._probehelper.reconstruct_carcass(pkt[ICMP].icmpdata.data)
                origttl = self._infer_orig_ttl(pkt[IPv4].ttl)
                if p.has_header(self._probehelper.klass):
                    # ttl stuffed into ipid of previously sent 
                    # pkt is unreliable
                    seq, ident = self._probehelper.decode_carcass(p)
                    if ident == self._pktident and p[IPv4].dst == self._dest:
                        self._probe_queue.put_nowait((ts,seq,pkt[IPv4].src,origttl,ProbeDirection.Incoming))
                        return

        # identify our outgoing TCP or UDP probe packet.  ICMP is caught
        # in prevous elif
        elif pkt.has_header(self._probehelper.klass): 
            seq,ident = self._probehelper.decode_carcass(pkt)
            origttl = pkt[IPv4].ttl
            if ident == self._pktident:
                self._probe_queue.put_nowait((ts,seq,pkt[IPv4].src,origttl,ProbeDirection.Outgoing))
                return

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

    def metadata(self):
        xmeta = {}
        xmeta['libpcap_stats'] = self._get_pcap_stats()
        xmeta['pkts_received'] = self._num_recv 
        xmeta['tstamps'] = self._results.all()
        return xmeta

    def show_status(self):
        pass


def create(config):
    '''
    Configuration options:
        interface=interface_name
    '''
    if not 'interface' in config:
        raise ConfigurationError("Missing 'interface' config item for RTT monitor.")
    interface = config.pop('interface')
    validiface = list(net_if_stats().keys())
    if interface not in net_if_stats().keys():
        raise ConfigurationError("Invalid interface name {} for RTT monitor (valid names: {})".format(interface, ','.join(validiface)))

    dodecode = config.pop('decode', False)

    prober = PcapReceiverSource(interface, dodecode)
    return SystemObserver(prober, _gamma_observer(1))
