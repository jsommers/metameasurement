import sys
import re
from ipaddress import IPv4Network
from collections import defaultdict
from subprocess import check_output, PIPE, STDOUT

from pytricia import PyTricia
from switchyard.lib.userlib import *

class InterfaceInfo(object):
    def __init__(self, swyif):
        self._ethsrc = swyif.ethaddr 
        self._ipsrc = swyif.ipaddr
        self._ifname = swyif.name
        self._ethdst = EthAddr("00:00:00:00:00:00")
        self._ipdst = IPv4Address("0.0.0.0")

    def __str__(self):
        return "{} {}-{} -> {}-{}".format(self._ifname,
            self._ethsrc, self._ipsrc, self._ethdst, self._ipdst)

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

    @ipdst.setter
    def ipdst(self, value):
        self._ipdst = IPv4Address(value)

    @property
    def name(self):
        return self._ifname

# def get_iface_addrs(name):
#     cproc = check_output("ifconfig {}".format(name), shell=True,
#         universal_newlines=True)
#     s = cproc.stdout    
#     ethpat = re.compile(r'(ether|HWaddr)\s+(?P<addr>[0-9a-fA-F]{1,2}(:[0-9a-fA-F]{1,2}){5})', re.MULTILINE)
#     ipv4pat = re.compile(r'(inet|inet addr:)\s+(?P<addr>\d+(\.\d+){3})', re.MULTILINE)
#     ethaddr = "0:0:0:0:0:0"
#     ipv4 = IPv4Address("0.0.0.0")
#     mobj = ethpat.search(s)
#     if mobj:
#         ethaddr = mobj.group('addr')
#     mobj = ipv4pat.search(s)
#     if mobj:
#         ipv4 = IPv4Address(mobj.group('addr'))
#     return ethaddr,ipv4

def read_netstat(synet):
    def get_value(name, info, headers):
        if name == 'dst':
            dstip = info[headers.index('Destination')]
            if dstip == 'default':
                dstip = '0.0.0.0/0'
            if 'Genmask' in headers:
                dstip = "{}/{}".format(dstip,info[headers.index('Genmask')])
            try:
                rv = IPv4Network(normalize_ipv4(dstip), strict=False)
                return rv
            except:
                return None

        elif name == 'gw':
            return info[headers.index('Gateway')]
        elif name == 'iface':
            if 'Iface' in headers:
                return info[headers.index('Iface')]
            elif 'Netif' in headers:
                return info[headers.index('Netif')]

    def is_ipaddr(s):
        return re.match(r'\d+(\.\d+){2,3}', s)

    def normalize_ipv4(s):
        if '/' in s:
            prefix,plen = s.split('/')
            while prefix.count('.') < 3:
                prefix += ".0"
            s = '/'.join((prefix,plen))
        return s

    def is_ethaddr(s):
        return re.match(r'[0-9a-fA-F]{1,2}(:[0-9a-fA-F]{1,2}){5}', s)
        
    routes = PyTricia(32)
    gwips = defaultdict(list)

    cmd = "netstat -r -n"
    if sys.platform == 'darwin':
        cmd += ' -f inet'
    s = check_output(cmd, shell=True, universal_newlines=True)

    headers = []
    for line in s.split('\n'):
        dst = gwip = iface = dsteth = None
        if line.startswith('Destination'):
            headers = line.split()
        elif len(line) > 0 and \
          (line[0].isdigit() or line.startswith('default')):
            info = line.split()
            dst = get_value('dst', info, headers)
            if dst is None:
                continue
            gwip = get_value('gw', info, headers)
            iface = get_value('iface', info, headers)

            # skip localhost and multicast
            if dst.is_multicast or dst.is_loopback:
                continue

            try:
                p = synet.port_by_name(iface)
            except KeyError:
                continue

            if is_ipaddr(gwip):
                gwip = IPv4Address(gwip)
            elif is_ethaddr(gwip):
                dsteth = EthAddr(gwip)
                gwip = None
            else:
                gwip = IPv4Address('0.0.0.0')

            # print(dst,gwip,dsteth,iface)

            if routes.has_key(dst):
                ii = routes[dst]
            else:
                ii = InterfaceInfo(synet.port_by_name(iface))
                if dst.prefixlen == 32:
                    ii.ipdst = dst.network_address
                routes[dst] = ii

            if gwip is not None and gwip != IPv4Address("0.0.0.0"):
                ii.ipdst = gwip

            if dsteth is not None:
                for prefix in routes:
                    ii = routes[prefix] 
                    if IPv4Network(prefix) == dst:
                        ii.ethdst = dsteth
                        ii.ipdst = dst.network_address
                    elif ii.ipdst == dst or ii.ipdst == dst.network_address:
                        ii.ethdst = dsteth

    #for dst in routes:
    #    ii = routes[dst]
    #    print("dst {} is through {}".format(dst, ii))

    return routes

if __name__ == '__main__':
    read_netstat()

