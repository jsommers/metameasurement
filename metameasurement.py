import sys
import re
import asyncio
import signal
from time import time
import functools
from ipaddress import IPv4Network
from collections import defaultdict
import logging

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
    def __init__(self, debug):
        self._asyncloop = asyncio.SelectorEventLoop()
        asyncio.set_event_loop(self._asyncloop)
        self._running = True
        self._asyncloop.add_signal_handler(signal.SIGINT, self._sig_catcher)
        self._asyncloop.add_signal_handler(signal.SIGTERM, self._sig_catcher)
        self._ports = {}
        self._ifinfo = self._routes = None
        self._arp_cache = {}
        self._arp_queue = asyncio.Queue()
        self._icmp_queue = asyncio.Queue()
        self._debug = debug
        self._log = logging.getLogger('mm')
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

    def _cleanup(self):
        # close pcap devices
        for ifname,pcapdev in self._ports.items():
            self._log.info("Closing {}: {}".format(ifname, pcapdev.stats()))
            pcapdev.close()
        self._asyncloop.stop()

    def _sig_catcher(self, *args):
        self._log.debug("Caught signal")
        self._asyncloop.call_soon(self._cleanup)

    def _packet_arrival_callback(self, pcapdev=None):
        p = pcapdev.recv_packet_or_none()
        name = pcapdev.name
        pkt = decode_packet(pcapdev.dlt, p.raw)
        ts = p.timestamp
        ptup = (name,ts,pkt)

        if pkt.has_header(Arp) and \
            pkt[Arp].operation == ArpOperation.Reply: 
            # and \
            #pkt[Arp].targetprotoaddr == ifinfo.ipdst:
            log_debug("Got ARP response: {}".format(pkt[Arp]))
            #result = await self._arp_queue.put(ptup)
            # return pkt[Arp].targethwaddr
        elif pkt.has_header(ICMP):
            pass
            # result = await self._icmp_queue.put(ptup)
        else:
            print("Ignoring packet {}".format(ptup))

    def _send_packet(self, intf, pkt):
        assert(intf in self._ports)
        assert(isinstance(pkt, Packet))
        pcapdev = self._ports[intf]
        pcapdev.send_packet(pkt.to_bytes())

    async def _do_arp(self, dst, intf):
        ifinfo = self._ifinfo[intf]
        arpreq = create_ip_arp_request(ifinfo.ethsrc, 
            ifinfo.ipsrc.ip, dst)
        fareth = "00:00:00:00:00:00"
        self._send_packet(ifinfo.name, arpreq)

    async def _ping(self, dst):
        print("send ping to {}".format(dst))
        nh = self._routes[dst]
        print(nh)
        ethaddr = await self._do_arp(nh.nexthop, nh.interface)
        print("ethaddr from coroutine: {}".format(ethaddr))

    def run(self):
        self._ifinfo = get_interface_info(self._ports.keys())
        self._routes = get_routes(self._ifinfo)

        for intf in self._ifinfo:
            print("{} -> {}".format(intf, self._ifinfo[intf]))
        for prefix in self._routes:
            print("{} -> {}".format(prefix, self._routes[prefix]))

        # self._asyncloop.create_task(self._ping('149.43.80.25'))

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
    m = MeasurementObserver(True)
    m.add_port('en0', 'icmp or arp')
    m.run()

if __name__ == '__main__':
    main()

