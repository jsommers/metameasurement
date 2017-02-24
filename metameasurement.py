from threading import Thread, Lock, Barrier
from subprocess import Popen, PIPE, STDOUT, run
from time import time
import re

from pytricia import PyTricia
from switchyard.lib.userlib import *

class InterfaceInfo(object):
    def __init__(self, swyardintf, gwip):
        self._ethsrc = EthAddr(swyardintf.ethaddr)
        self._ipsrc = IPv4Address(swyardintf.ipaddr)
        self._ifname = swyardintf.name
        self._ethdst = EthAddr("00:00:00:00:00:00")
        self._ipdst = IPv4Address(gwip)

    def make_ethhdr(self):
        return Ethernet(src=self._ethsrc, dst=self._ethdst)

    @property
    def ethsrc(self):
        return self._ethsrc

    @property
    def ethdst(self):
        return self._ethdst

    @ethdst.setter
    def ethdst(self, value):
        self._ethdst = EthAddr(value)

    @property
    def ipsrc(self):
        return self._ipsrc

    @property
    def ipdst(self):
        return self._ipdst

    @property
    def name(self):
        return self._ifname


class MeasurementObserver(object):
    def __init__(self, net, *args, **kwargs):
        self._net = net
        self._running = True
        self._pyt = PyTricia(32)

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

    def _gather_local_netinfo(self):
        cproc = run("netstat -r -n -f inet", shell=True,
            universal_newlines=True, stdout=PIPE, stderr=STDOUT) 
        _gwips = {}
        for line in cproc.stdout.split('\n'):
            if len(line) > 0 and \
                (line[0].isdigit() or line.startswith('default')):
                info = line.split()
                dst = info[0]
                if dst == 'default':
                    dst = '0.0.0.0/0'
                gwip = info[1]                
                if not re.match('\d+\.\d+\.\d+\.\d+', gwip):
                    continue
                iface = info[-1]
                # skip localhost and multicast
                if dst.startswith('224') or dst.startswith('127'):
                    continue
                _gwips[iface] = gwip

        for p in self._net.ports():
            dest = str(p.ipinterface.network)
            self._pyt[dest] = InterfaceInfo(p, _gwips[p.name])

        for prefix in self._pyt:
            ii = self._pyt[prefix]
            ii.ethdst = self._do_arp(ii)
            log_info("Prefix: {} gwip {} ethaddr {}".format(
                prefix, ii.ipdst, ii.ethdst))

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
        self._gather_local_netinfo()

        #self._swthread = Thread(target=self._swyard_loop)
        #self._swthread.start()
        #self._prepost_profile()
        # self._runtool()


def main(net, *args, **kwargs):
    m = MeasurementObserver(net)
    m.run()
    net.shutdown()
