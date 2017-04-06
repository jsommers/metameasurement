import sys
import asyncio
import signal
from time import time
from ipaddress import IPv4Network
from collections import defaultdict
import logging

from switchyard.lib.userlib import *
from switchyard import pcapffi


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
        self._interface = None
        self._pcapdev = None
        self._received = 0
        self._packets = []
        self._debug = debug
        self._status_interval = 5
        self._log = logging.getLogger('metabench')
        logging.basicConfig(format='%(asctime)s | %(name)s | %(levelname)s | %(message)s')

        if self._debug:
            logging.basicConfig(level=logging.DEBUG)
            self._log.setLevel(logging.DEBUG)
            self._asyncloop.set_debug(True)
        else:
            logging.basicConfig(level=logging.INFO)

    def set_port(self, ifname, filterstr=''):
        self._interface = ifname
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

        w = p.activate()
        if w != 0:
            wval = pcapffi.PcapWarning(w)
            self._log.warn("Warning on activation: {}".format(wval.name))

        p.blocking = False
        p.set_direction(pcapffi.PcapDirection.InOut)
        p.set_filter(filterstr)

        self._pcapdev = p
        self._asyncloop.add_reader(p.fd, self._packet_arrival_callback)

    def _cleanup(self):
        self._log.info("Closing {}: {}".format(self._interface, self._pcapdev.stats()))
        self._pcapdev.close()
        self._asyncloop.stop()

    def _sig_catcher(self, *args):
        self._log.debug("Caught signal")
        self._asyncloop.call_soon(self._cleanup)
        for t in asyncio.Task.all_tasks():
            t.cancel()

    def _packet_arrival_callback(self):
        while True:
            p = self._pcapdev.recv_packet_or_none()
            if p is None:
                return

            name = self._pcapdev.name
            pkt = decode_packet(self._pcapdev.dlt, p.raw)
            ts = p.timestamp
            ptup = (ts,pkt)
            self._packets.append(ptup)
            self._received += 1

    async def _status(self):
        while True:
            try:
                await asyncio.sleep(self._status_interval)
            except asyncio.CancelledError:
                break
            self._log.info("{} receive counter".format(self._received))

    def run(self):
        asyncio.ensure_future(self._status())
        try:
            self._asyncloop.run_forever()
        finally:
            self._asyncloop.close()

        self._log.info("Received {} packets".format(len(self._packets)))
        self._log.info("Final receive counter: {}".format(self._received))


def main():
    m = MeasurementObserver(True)
    m.set_port('en0', '')
    m.run()

if __name__ == '__main__':
    main()

