from threading import Thread, Lock, Barrier
from subprocess import check_output, PIPE, STDOUT
from time import time
from ipaddress import IPv4Network
from collections import defaultdict
import sys
import re

from switchyard.lib.userlib import *
from localnet import InterfaceInfo, read_netstat


class MeasurementObserver(object):
    def __init__(self, net, *args, **kwargs):
        self._net = net
        self._running = True

    def _swyard_loop(self):
        while True:
            if not self._running:
                break

            try:
                recvdata = self._net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                self._running = False
                return

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
        self._routes = read_netstat(self._net)

        #self._swthread = Thread(target=self._swyard_loop)
        #self._swthread.start()
        #self._prepost_profile()
        # self._runtool()


def main(net, *args, **kwargs):
    m = MeasurementObserver(net)
    m.run()
    net.shutdown()
