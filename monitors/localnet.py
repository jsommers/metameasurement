import sys
import re
from ipaddress import IPv4Network, IPv4Interface, IPv4Address
from collections import defaultdict
from subprocess import check_output, PIPE, STDOUT, getstatusoutput
import socket

from pytricia import PyTricia

from switchyard.pcapffi import pcap_devices
from switchyard.lib.interface import InterfaceType
from switchyard.lib.address import *

from psutil import net_if_addrs

__all__ = ['NextHop', 'InterfaceInfo', 'get_interface_info', 'get_routes', \
    'read_system_arp_cache']


class NextHop(object):
    def __init__(self, network, interface, ipaddr):
        self._network = network
        self._interface = interface
        self._ipaddr = ipaddr

    @property
    def destination(self):
        return self._network

    @property
    def interface(self):
        return self._interface

    @property
    def nexthop(self):
        return self._ipaddr

    def __str__(self):
        return "{} -> {} {}".format(self._network,
            self._interface, self._ipaddr)


class InterfaceInfo(object):
    def __init__(self, name, localeth, localip, ifnum, iftype):
        self._ethsrc = localeth
        self._ipsrc = localip
        self._ifname = name
        self._ifnum = ifnum
        self._iftype = iftype

    def __str__(self):
        return "{} {} {} {} {}".format(self._ifname, self._ifnum, self._iftype,
            self._ethsrc, self._ipsrc)

    def make_ethhdr(self):
        return Ethernet(src=self._ethsrc, dst=self._ethdst)

    @property
    def ethsrc(self):
        return self._ethsrc

    @property
    def ipsrc(self):
        return self._ipsrc

    @property
    def name(self):
        return self._ifname


def read_system_arp_cache():
    arp_map = {}
    cmd = "/usr/sbin/arp -na"
    try:
        s = check_output(cmd, shell=True, universal_newlines=True)
    except:
        return arp_map

    ethip = re.compile(r'(?P<ip>(\d{1,3}\.){3}\d{1,3})[\)\s\w]+ (?P<eth>([a-fA-F0-9]{1,2}:){5}[a-fA-F0-9]{1,2})')
    for line in s.split('\n'):
        mobj = ethip.search(line)
        if mobj:
            # print(mobj.group('ip'), mobj.group('eth'))
            arp_map[IPv4Address(mobj.group('ip'))] = EthAddr(mobj.group('eth'))
    return arp_map
        

def get_interface_info(ifname_list):
    def assemble_devinfo(pcapdev):
        '''
        Internal fn.  Assemble information on each interface/
        device that we know about, i.e., its MAC address and configured
        IP address and prefix.
        '''
        if pcapdev.isloop:
            iftype = InterfaceType.Loopback
        else:
            if sys.platform == 'linux':
                st,output = getstatusoutput(["iwconfig", pcapdev.name])
                if "no wireless extensions" in output:
                    iftype = InterfaceType.Wired
                else:
                    iftype = InterfaceType.Wireless
            elif sys.platform == 'darwin':
                iftype = InterfaceType.Unknown
            else:
                iftype = InterfaceType.Unknown

        ifinfo = net_if_addrs()
        macaddr = ipaddr = mask = None
        if sys.platform == 'darwin':
            layer2addrfam = socket.AddressFamily.AF_LINK
        elif sys.platform == 'linux':
            layer2addrfam = socket.AddressFamily.AF_PACKET
        else:
            layer2addrfam = None # fail

        for addrinfo in ifinfo[pcapdev.name]:
            if addrinfo.family == socket.AddressFamily.AF_INET:
                xaddr = IPv4Address(addrinfo.address)
                if xaddr.is_link_local: # ignore any link-local addrs
                    continue
                ipaddr = IPv4Address(addrinfo.address)
                mask = IPv4Address(addrinfo.netmask)
            elif addrinfo.family == layer2addrfam:
                macaddr = EthAddr(addrinfo.address)

        ifnum = socket.if_nametoindex(pcapdev.name)
        return InterfaceInfo(pcapdev.name, macaddr, IPv4Interface("{}/{}".format(ipaddr, mask)), ifnum, iftype)

    pdevs = [ p for p in pcap_devices() if p.name in ifname_list ]
    if not pdevs:
        print("No interfaces found to use")
        return {}
    interfaces = [ assemble_devinfo(p) for p in pdevs ]
    ifdict = dict([(intf.name,intf) for intf in interfaces])
    return ifdict

def get_routes(ifdict):
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
        dst = gwip = iface = None
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

            if iface not in ifdict:
                continue

            if is_ipaddr(gwip):
                gwip = IPv4Address(gwip)
            elif is_ethaddr(gwip):
                continue
            else:
                gwip = IPv4Address('0.0.0.0')

            # print(dst,gwip,iface)

            if routes.has_key(dst):
                # print("Already have nh for {}: {}".format(dst, routes[dst]))
                ii = routes[dst]
            else:
                nh = NextHop(dst, iface, gwip)
                routes[dst] = nh

    return routes

if __name__ == '__main__':
    ifdict = get_interface_info(['en0'])
    routes = get_routes(ifdict)

    for ifx in ifdict:
        print("{}: {}".format(ifx, ifdict[ifx]))

    for dst in routes:
        ii = routes[dst]
        print("{}: {}".format(dst, ii))

    d = load_system_arp_cache()
    print(d)
