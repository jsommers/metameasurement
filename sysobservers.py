import sys
from abc import abstractmethod
import asyncio
from time import sleep, time
import re
import socket
import signal
import logging
import functools
import random
import os
from math import isinf

from psutil import cpu_times_percent, disk_io_counters, \
    net_io_counters, virtual_memory
from numpy import min_scalar_type, iinfo

from switchyard.lib.userlib import *
from switchyard import pcapffi
from localnet import *

__all__ = ['CPUDataSource', 'IODataSource', 'NetIfDataSource', 
    'MemoryDataSource', 'SystemObserver', 'ResultsContainer',
    'ICMPHopLimitedRTTSource']


def _compute_diff_with_wrap(curr, last):
    '''
    Correctly handle computing differences on counters that have
    overflowed.
    '''
    diff = curr - last
    if diff >= 0:
        return diff
    dtype = min_scalar_type(last)
    dtypemax = iinfo(dtype).max
    return curr + (dtypemax - last)


class DataSource(object):
    '''
    A data source for some system tool from which host performance
    measures can be gathered, e.g., cpu, ioperf, net, memory, etc.
    It simply must define a __call__ method that returns a dictionary
    containing a data observation *or* calls the internal method
    _add_result with a data observation dictionary as an argument. 
    '''
    def __init__(self):
        self._done = False

    @abstractmethod
    def __call__(self):
        '''
        Should return a dictionary with keyword:value observations.
        '''
        raise NotImplementedError()

    def stop(self):
        self._done = True

    def cleanup(self):
        pass

    def setup(self, metamaster, resultscontainer):
        pass


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


class ICMPHopLimitedRTTSource(DataSource):
    '''
    Monitor RTTs to some number of hops using ICMP echo requests with low
    TTLs.  Uses Switchyard libraries to handle packet construction/emission/reception.
    '''
    def __init__(self, numhops=1, dest="8.8.8.8"):
        DataSource.__init__(self)
        self._dest = dest # by default, direct toward GOOG public DNS anycast
        self._numhops = numhops
        self._icmpseq = 1
        self._arp_cache = {}
        self._arp_queue = asyncio.Queue()
        self._icmp_queue = asyncio.Queue()
        self._ports = {}
        if sys.platform == 'linux':
            self._sendports = {}
        self._log = logging.getLogger('mm')
        self._monfut = asyncio.Future()
        self._ifinfo = self._routes = None
        self._icmpident = os.getpid()%65536
        self._seqhash = { ICMPType.EchoRequest: {}, 
                          ICMPType.TimeExceeded: {} }
        asyncio.ensure_future(self._ping_collector(self._monfut))

    def add_port(self, ifname, filterstr=''):
        p = pcapffi.PcapLiveDevice.create(ifname)
        p.snaplen = 80
        p.set_promiscuous(True)
        p.set_timeout(1)

        # choose the "best" timestamp available:
        # highest number up to 3 (don't use unsynced adapter stamps)

        stamptypes = p.list_tstamp_types()
        if len(stamptypes):
            if pcapffi.PcapTstampType.AdapterUnsync in stamptypes:
                stamptypes.remove(pcapffi.PcapTstampType.AdapterUnsync)
            beststamp = max(stamptypes)
            try:
                p.set_tstamp_type(beststamp)
                self._log.info("Set timestamp type to {}".format(beststamp))
            except:
                self._log.warn("Couldn't set timestamp type to the advertised value {}".format(beststamp))

        try:
            p.tstamp_precision = pcapffi.PcapTstampPrecision.Nano
            self._log.info("Using nanosecond timestamp precision.")
        except:
            self._log.info("Using microsecond timestamp precision.")

        w = p.activate()
        if w != 0:
            self._log.warn("Warning on activation: {}".format(w))

        p.set_direction(pcapffi.PcapDirection.InOut)
        p.set_filter("icmp or arp")

        self._ports[ifname] = p
        if sys.platform == 'linux':
            # on Linux, create a separate packet/raw socket for sending due to
            # linux-only limitations.  In particular, unlike other platforms (BSDish),
            # we cannoot receive the same packet as sent on a device (and thus get
            # hw timestamps on send).  Thus, we create a separate device for sending
            # and can receive both outgoing (that we send) and incoming packets.
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, EtherType.IPv4)
            s.bind((ifname, EtherType.IPv4))  
            self._sendports[ifname] = s

        asyncio.get_event_loop().add_reader(p.fd, 
            functools.partial(self._packet_arrival_callback, pcapdev=p))

    def __call__(self):
        asyncio.ensure_future(self._emiticmp(self._dest))            

    def _packet_arrival_callback(self, pcapdev=None):
        while True:
            p = pcapdev.recv_packet_or_none()
            if p is None:
                break

            name = pcapdev.name
            pkt = decode_packet(pcapdev.dlt, p.raw)
            ts = p.timestamp
            ptup = (name,ts,pkt)

            if pkt.has_header(Arp) and \
              pkt[Arp].operation == ArpOperation.Reply: 
                a = pkt[Arp]
                #self._log.debug("Got ARP response: {}-{}".format(a.senderhwaddr, a.senderprotoaddr))
                self._arp_queue.put_nowait((a.senderhwaddr, a.senderprotoaddr))
            elif pkt.has_header(ICMP):
                #self._log.debug("Got something ICMP")
                if (pkt[ICMP].icmptype == ICMPType.EchoReply and \
                    pkt[ICMP].icmpdata.identifier == self._icmpident):
                    seq = pkt[ICMP].icmpdata.sequence
                    #self._log.debug("Got ICMP response on {} at {}: {}".format(name, ts, pkt))
                    self._icmp_queue.put_nowait((ts,seq,pkt[IPv4].src,pkt))
                elif pkt[ICMP].icmptype == ICMPType.TimeExceeded:
                    p = Packet(pkt[ICMP].icmpdata.data, first_header=IPv4) 
                    if p[ICMP].icmpdata.identifier == self._icmpident:
                        #self._log.debug("Got ICMP excerr on {} at {}: {}".format(name, ts, pkt))
                        #self._log.debug("orig pkt: {}".format(p))
                        seq = p[ICMP].icmpdata.sequence
                        ident = p[ICMP].icmpdata.identifier
                        self._icmp_queue.put_nowait((ts,seq,pkt[IPv4].src,pkt))
                elif pkt[ICMP].icmptype == ICMPType.EchoRequest and \
                    pkt[ICMP].icmpdata.identifier == self._icmpident:
                        #self._log.debug("Got our request pkt on {} at {}: {}".format(name, ts, pkt))
                        seq = pkt[ICMP].icmpdata.sequence
                        self._icmp_queue.put_nowait((ts,seq,pkt[IPv4].src,pkt))
            else:
                self._log.debug("Ignoring packet from {}: {}".format(name, pkt))

    def _send_packet(self, intf, pkt):
        if sys.platform == 'linux':
            dev = self._sendports[intf]
            dev.send(pkt.to_bytes()) 
        else:
            dev = self._ports[intf]
            dev.send_packet(pkt.to_bytes()) 

    async def _do_arp(self, dst, intf):
        if dst in self._arp_cache:
            return self._arp_cache[dst]
        ifinfo = self._ifinfo[intf]
        arpreq = create_ip_arp_request(ifinfo.ethsrc, 
            ifinfo.ipsrc.ip, dst)
        fareth = "00:00:00:00:00:00"
        self._send_packet(ifinfo.name, arpreq)
        while True:
            try:
                ethaddr,ipaddr = await self._arp_queue.get()
            except asyncio.CancelledError:
                break
            self._arp_cache[ipaddr] = ethaddr
            if ipaddr == dst:
                break
        return ethaddr

    async def _emiticmp(self, dst):
        nh = self._routes[dst]
        try:
            ethaddr = await self._do_arp(nh.nexthop, nh.interface)
        except asyncio.CancelledError:
            return
        thisintf = self._ifinfo[nh.interface]
        pkt = Ethernet(src=thisintf.ethsrc, dst=ethaddr) + \
            IPv4(src=thisintf.ipsrc.ip, dst=dst, protocol=IPProtocol.ICMP,
                ttl=1) + \
            ICMP(icmptype=ICMPType.EchoRequest,
                identifier=self._icmpident,
                sequence=self._icmpseq)
        self._log.debug("Emitting icmp echo request: {}".format(pkt))
        seq = self._icmpseq
        xhash = self._seqhash[ICMPType.EchoRequest]
        self._icmpseq += 1
        if self._icmpseq == 65536:
            self._icmpseq = 1
        xhash[seq] = time()
        self._send_packet(nh.interface, pkt)

    async def _ping_collector(self, fut):
        A = ICMPType.EchoRequest
        B = ICMPType.TimeExceeded
        seqhash = self._seqhash
        self._num_probes = 0

        while not self._done:
            try:
                ts,seq,src,pkt = await self._icmp_queue.get()
            except asyncio.CancelledError:
                break
            # if we receive a pkt we send, timestamp gets updated (overwritten)
            xhash = seqhash[pkt[ICMP].icmptype]
            xhash[seq] = ts
            if seq in seqhash[A] and seq in seqhash[B]:
                rtt = seqhash[B].pop(seq) - seqhash[A].pop(seq)
                self._add_result({'icmprtt':rtt,'seq':seq})
                self._num_probes += 1

        echo = seqhash[A]
        exc = seqhash[B]

        for seq in sorted(echo.keys()):
            if seq in exc:
                rtt = exc[seq] - echo[seq]
            else:
                rtt = float('inf')
            self._add_result({'icmprtt':rtt,'seq':seq})
            self._num_probes += 1
        fut.set_result(self._num_probes)

    def setup(self, metamaster, resultscontainer):
        self._ifinfo = get_interface_info(self._ports.keys())
        self._routes = get_routes(self._ifinfo)
        self._add_result = resultscontainer.add_result
        self._add_metadata = metamaster.add_metadata

        # debugging: dump out all interface and route info
        # for intf in self._ifinfo:
        #     print("{} -> {}".format(intf, self._ifinfo[intf]))
        # for prefix in self._routes:
        #     print("{} -> {}".format(prefix, self._routes[prefix]))

    def cleanup(self):
        # close pcap devices and get stats from them
        pcapstats = {}
        for ifname,pcapdev in self._ports.items():
            s = pcapdev.stats()
            pcapstats[ifname] = {'recv':s.ps_recv,
                'pcapdrop':s.ps_drop, 'ifdrop':s.ps_ifdrop}
            self._log.info("Closing {}: {}".format(ifname, s))
            pcapdev.close()
        if sys.platform == 'linux':
            for ifname,rawsock in self._sendports.items():
                self._log.info("Closing rawsock for sending on {}".format(ifname, s))
                rawsock.close()

        self._add_metadata('libpcap_stats', pcapstats)
        self._add_metadata('icmpsource_config', {
                'hops_monitored': self._numhops,
                'total_probes_emitted': self._num_probes,
            })


class CPUDataSource(DataSource):
    '''
    Monitor CPU usage (via psutil module)
    '''
    def __init__(self):
        DataSource.__init__(self)
        x = cpu_times_percent() # as per psutil docs: first call will give rubbish 
        self._keys = [ a for a in dir(x) if not a.startswith('_') and \
            not callable(getattr(x,a)) ]

    def __call__(self):
        sample = cpu_times_percent()
        return { k:getattr(sample,k) for k in self._keys }


class IODataSource(DataSource):
    '''
    Monitor disk IO counters via psutil.  The psutil call just yields the current
    counter values; internally we keep last sample and only store differences.
    '''
    def __init__(self):
        DataSource.__init__(self)
        x = self._lastsample = disk_io_counters(perdisk=True) # as per psutil docs: first call will give rubbish 
        self._disks = x.keys()
        d1 = list(self._disks)[0]
        self._keys = [ a for a in dir(x[d1]) if not a.startswith('_') and \
            not callable(getattr(x[d1],a)) ]

    def __call__(self):
        sample = disk_io_counters(perdisk=True)
        rd = {
          '_'.join((d,k)):_compute_diff_with_wrap(getattr(sample[d], k), \
                                     getattr(self._lastsample[d], k)) \
                    for k in self._keys for d in self._disks 
        }
        self._lastsample = sample
        return rd


class NetIfDataSource(DataSource):
    '''
    Monitor network interface counters.  Can be constructed with one or more names
    (strings) of network interfaces, or nothing to monitor all interfaces.  The psutil
    call just yields current counter values; internally we keep last sample and only
    store differences.
    '''
    def __init__(self, *nics_of_interest):
        DataSource.__init__(self)
        x = self._lastsample = net_io_counters(pernic=True) # as per psutil docs: first call will give rubbish 
        if not nics_of_interest:
            self._nics = x.keys()
        else:
            self._nics = [ n for n in x.keys() if n in nics_of_interest ]
        d1 = list(self._nics)[0]
        self._keys = [ a for a in dir(x[d1]) if not a.startswith('_') and \
            not callable(getattr(x[d1],a)) ]

    def __call__(self):
        sample = net_io_counters(pernic=True)
        rd = {
          '_'.join((n,k)):_compute_diff_with_wrap(getattr(sample[n], k), \
                                     getattr(self._lastsample[n], k)) \
                    for k in self._keys for n in self._nics
        }
        return rd


class MemoryDataSource(DataSource):
    '''
    Monitor memory usage via psutil.
    '''
    def __init__(self):
        DataSource.__init__(self)
        x = virtual_memory() # as per psutil docs: first call will give rubbish 
        self._keys = [ a for a in dir(x) if not a.startswith('_') and \
            not callable(getattr(x,a)) ]

    def __call__(self):
        sample = virtual_memory()
        return dict([ (k,getattr(sample,k)) for k in self._keys ]) 


class ResultsContainer(object):
    def __init__(self):
        self._results = [] # list of tuples: (time, {observation dict})

    def add_result(self, d):
        now = time()
        self._results.append( (now, d) )

    def last_result(self, key):
        if not self._results:
            return None
        return self._results[-1][1][key]

    def compute(self, fn, key, lastn=0):
        if not self._results:
            return None
        return fn([ t[1][key] for t in self._results[-lastn:] if not isinf(t[1][key]) ])

    def summary(self, fn):
        if not self._results:
            return None
        klist = list(self._results[0][1].keys())
        vlist = [ self.compute(fn, k) for k in klist ]
        return dict(zip(klist,vlist))

    def timeseries(self, key):
        if not self._results:
            return None
        ts = [ t[0] for t in self._results ]
        val = [ t[1][key] for t in self._results ]
        return (ts, val)

    def __str__(self):
        return str(self.summary(mean))

    def __repr__(self):
        return repr(self.summary(mean))

    def all(self):
        return self._results

    def drop_first(self):
        if self._results:
            self._results.pop(0)


class SystemObserver(object):
    def __init__(self, datasource, intervalfn, dropfirst=True):
        self._source = datasource
        self._results = ResultsContainer()
        self._done = False
        assert(callable(intervalfn))
        self._intervalfn = intervalfn
        self._dropfirst = dropfirst # for psutil data, best to drop the first measurement

    def setup(self, metamaster):
        self._source.setup(metamaster, self._results)

    async def __call__(self):
        while True:
            sample = self._source()
            if sample is not None:
                self._results.add_result(sample)

            if self._done or \
                asyncio.Task.current_task().cancelled():
                break

            try:
                await asyncio.sleep(self._intervalfn())
            except asyncio.CancelledError:
                break

        if self._dropfirst:
            self._results.drop_first()

    def stop(self):
        self._done = True
        self._source.stop()
        asyncio.get_event_loop().call_soon(self._source.cleanup)

    def set_intervalfn(self, fn):
        assert(callable(fn))
        self._intervalfn = fn

    @property
    def results(self):
        return self._results


def sig_catch(*args):
    for t in asyncio.Task.all_tasks():
        t.cancel()
    asyncio.get_event_loop().call_later(0.5, stop_world)

def stop_world():
    asyncio.get_event_loop().stop()


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGINT, sig_catch)

    cpu = SystemObserver(CPUDataSource(), lambda: random.expovariate(1.0))
    f1 = asyncio.ensure_future(cpu())

    io = SystemObserver(IODataSource(), lambda: random.uniform(2.0,2.0))
    f2 = asyncio.ensure_future(io())

    net = SystemObserver(NetIfDataSource('en0'), lambda: random.uniform(2.0, 2.0))
    f3 = asyncio.ensure_future(net())

    mem = SystemObserver(MemoryDataSource(), lambda: random.uniform(2.0, 2.0))
    f4 = asyncio.ensure_future(mem())

    try:
        loop.run_forever()
    except:
        pass
    finally:
        loop.close()

    from statistics import mean, stdev, median, variance

    print(cpu.results.all())
    print(io.results.all())
    print(net.results.all())
    print(mem.results.summary(max))
    print(net.results.compute(max, 'en0_dropin'))
    print(mem.results.compute(mean, 'percent'))
