import sys
import re
import asyncio
import signal
from time import time
import functools
from ipaddress import IPv4Network
from collections import defaultdict

from switchyard.lib.userlib import *
from switchyard import pcapffi

from localnet import get_interface_info, get_routes

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
    def __init__(self):
        self._asyncloop = asyncio.SelectorEventLoop()
        asyncio.set_event_loop(self._asyncloop)
        self._running = True
        signal.signal(signal.SIGINT, self._sig_catcher)
        signal.signal(signal.SIGTERM, self._sig_catcher)
        self._ports = {}
        self._ifinfo = self._routes = None

    def add_port(self, ifname, filterstr=''):
        # p = pcapffi.PcapLiveDevice('en0', filterstr="icmp")
        p = pcapffi.PcapLiveDevice(ifname, filterstr=filterstr)
        self._ports[ifname] = p
        self._asyncloop.add_reader(p.fd, 
            functools.partial(self._packet_arrival_callback, pcapdev=p))

    def _cleanup(self):
        # close pcap devices
        for ifname,pcapdev in self._ports.items():
            print("Closing {}: {}".format(ifname, pcapdev.stats()))
            pcapdev.close()

    def _sig_catcher(self, *args):
        self._asyncloop.stop()
        self._asyncloop.call_soon_threadsafe(self._cleanup)

#    def _swyard_loop(self):
#        while True:
#            if not self._running:
#                break
#
#            try:
#                recvdata = self._net.recv_packet(timeout=1.0)
#            except NoPackets:
#                continue
#            except Shutdown:
#                self._running = False
#                return

    def _packet_arrival_callback(self, pcapdev=None):
        p = pcapdev.recv_packet_or_none()
        name = pcapdev.name
        pkt = decode_packet(pcapdev.dlt, p.raw)
        ts = p.timestamp
        print(name,ts,pkt)

    def _do_arp(self, ifinfo):
        attempts = 3
        arpreq = create_ip_arp_request(ifinfo.ethsrc, 
            ifinfo.ipsrc, ifinfo.ipdst)
        fareth = "00:00:00:00:00:00"
        nextattempt = time()

        while attempts > 0:
            now = time()
            if now >= nextattempt:
                attempts -= 1
                self._net.send_packet(ifinfo.name, arpreq)
                nextattempt += 1

            try:
                ts,iface,pkt = self._net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                return
                    
            if pkt.has_header(Arp) and \
                pkt[Arp].operation == ArpOperation.Reply and \
                pkt[Arp].targetprotoaddr == ifinfo.ipdst:
                log_debug("Got ARP response: {}".format(pkt[Arp]))
                return pkt[Arp].targethwaddr

    def run(self):
        self._ifinfo = get_interface_info(self._ports.keys())
        self._routes = get_routes(self._ifinfo)

        for intf in self._ifinfo:
            print("{} -> {}".format(intf, self._ifinfo[intf]))
        for prefix in self._routes:
            print("{} -> {}".format(prefix, self._routes[prefix]))

        #self._swthread = Thread(target=self._swyard_loop)
        #self._swthread.start()
        #self._prepost_profile()
        # self._runtool()

#    # l = asyncio.get_event_loop()
#    # t = l.time()
#    # l.call_later(relsec)
#    # l.call_at(abssec)

        self._asyncloop.run_forever()
        self._asyncloop.close()


def main():
    m = MeasurementObserver()
    m.add_port('en0', 'icmp')
    m.run()

if __name__ == '__main__':
    main()
