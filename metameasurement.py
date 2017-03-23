import sys
import asyncio
import signal
from time import time, strftime, gmtime
import logging
from statistics import mean, stdev
import argparse
import subprocess
import json
import random

from sysobservers import *

VERSION = '2017.1.1'

class MetadataOrchestrator(object):
    def __init__(self, debug, fileprefix):
        self._asyncloop = asyncio.SelectorEventLoop()
        asyncio.set_event_loop(self._asyncloop)
        self._asyncloop.add_signal_handler(signal.SIGINT, self._sig_catcher)
        self._asyncloop.add_signal_handler(signal.SIGTERM, self._sig_catcher)
        self._debug = debug
        self._log = logging.getLogger('mm')
        self._monitors = {}
        self._done = False
        self._warmcooltime = 2
        self._fileprefix = fileprefix
        self._toolproc = None
        self._metadict = {}

        logging.basicConfig(format='%(asctime)s | %(name)s | %(levelname)s | %(message)s')

        if self._debug:
            logging.basicConfig(level=logging.DEBUG)
            self._log.setLevel(logging.DEBUG)
            self._asyncloop.set_debug(True)
        else:
            self._log.setLevel(logging.INFO)
            logging.basicConfig(level=logging.INFO)

    def add_metadata(self, key, obj):
        self._metadict[key] = obj

    def add_monitor(self, name, sysobserver):
        self._monitors[name] = sysobserver
        sysobserver.setup(self)
        asyncio.ensure_future(sysobserver())

    def _cleanup(self):
        self._asyncloop.stop()

    def _write_meta(self, commandline): 
        proc = subprocess.run("uname -a", shell=True, 
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        self._metadict['start'] = self._starttime
        self._metadict['end'] = self._endtime
        self._metadict['version'] = VERSION
        self._metadict['os'] = proc.stdout
        self._metadict['command'] = commandline
        try:
            self._metadict['commandoutput'] = self._toolfut.result()
            self._log.info("Command output: {}".format(self._toolfut.result()))
        except:
            self._metadict['commandoutput'] = "Error: command did not start and/or complete"
            self._log.info("Error: command did not start and/or complete.")

        self._metadict['monitors'] = {}
        for k,m in self._monitors.items():
            self._metadict['monitors'][k] = m.results.all()
            self._log.info("Monitor summary {}: {}".format(k, m.results.summary(mean)))

        timestr = strftime("%Y%m%d_%H%M%S", gmtime(self._starttime))
        filebase = "{}_{}".format(self._fileprefix, timestr)

        with open("{}.json".format(filebase), 'w') as outfile:
            json.dump(self._metadict, outfile)

    def _shutdown(self, future):
        self._log.debug("tool done; shutting down")
        if future:
            self._log.debug("result: {}".format(future.result()))
        self._asyncloop.call_later(self._warmcooltime, self._cleanup)
        self._done = True
        if self._toolproc and self._toolproc.returncode is None:
            self._toolproc.terminate()
        for m in self._monitors.values():
            m.stop()
        for t in asyncio.Task.all_tasks():
            t.cancel()

    def _sig_catcher(self, *args):
        self._shutdown(None)

    async def _run_tool(self, commandline, future):
        create = asyncio.create_subprocess_shell(commandline, 
                                                 stdout=asyncio.subprocess.PIPE,
                                                 stderr=asyncio.subprocess.PIPE)
        try:
            self._toolproc = await create
        except asyncio.CancelledError:
            return
        self._log.debug("Measurement tool started with pid {}".format(self._toolproc.pid))
        try:
            # assumes that data to read is not too large
            output = await self._toolproc.communicate() 
        except asyncio.CancelledError:
            return
        if not future.cancelled():
            future.set_result({'returncode': self._toolproc.returncode,
                               'stdout': output[0].decode('utf8'),
                               'stderr': output[1].decode('utf8')})


    def _start_tool(self, cmdline):
        asyncio.ensure_future(self._run_tool(cmdline, self._toolfut))
        self._toolfut.add_done_callback(self._shutdown)
        
    def run(self, commandline):
        self._starttime = time()
        self._log.info("Starting metadata measurement with verbose {} and commandline <{}>".format(
            self._debug, commandline))

        self._toolfut = asyncio.Future()
        self._cmdstart = self._asyncloop.call_later(self._warmcooltime, 
            self._start_tool, commandline)

        try:
            self._asyncloop.run_forever()
        finally:
            self._asyncloop.close()

        self._endtime = time()
        self._write_meta(commandline)

def get_gamma_params(probe_rate):
    '''
    Get Gamma (Erlang) distribution parameters for 
    probing.  Accepts probe rate (int) as a parameter
    (i.e., target probes to emit per second) and returns
    a tuple to splat into random.gammavariate
    '''
    shape = 4 # fixed integral shape 4-16; see SIGCOMM 06 and IMC 07 papers
    desired_mean = 1/probe_rate
    desired_scale = shape/desired_mean
    #print("desired scale",desired_scale)
    #print("xlambda",1/desired_scale)
    return shape,1/desired_scale

def main():
    parser = argparse.ArgumentParser(
            description='Automatic generation of active measurement metadata')
    parser.add_argument('-d', '-v', '--verbose', '--debug', 
                        dest='verbose', action='store_true', default=False,
                        help='Turn on verbose/debug output.')
    parser.add_argument('-f', '--fileprefix', dest='fileprefix', type=str, default='metadata',
                        help='Prefix for filename that includes metadata for a given run.')
    parser.add_argument('-c', '--command', dest='commandline', type=str, default='sleep 5',
                        help='The full command line for running an active measurement tool'
                             ' (note that the command line almost certainly needs to be quoted)')
    args = parser.parse_args()

    m = MetadataOrchestrator(args.verbose, args.fileprefix)
    m.add_monitor('cpu', SystemObserver(CPUDataSource(), lambda: random.uniform(1.0,1.0)))
    m.add_monitor('io', SystemObserver(IODataSource(), lambda: random.uniform(2.0,2.0)))
    m.add_monitor('netstat', SystemObserver(NetIfDataSource('en0'), lambda: random.uniform(1.0,1.0)))
    m.add_monitor('mem', SystemObserver(MemoryDataSource(), lambda: random.uniform(2.0,2.0)))

    rttsrc = ICMPHopLimitedRTTSource()
    rttsrc.add_port('en0', 'icmp or arp')
    gparms = get_gamma_params(2) # init target rate, 2 probes/sec
    m.add_monitor('rtt', SystemObserver(rttsrc, lambda: random.gammavariate(*gparms)))

    commandline = "sleep 5"
    m.run(args.commandline)

if __name__ == '__main__':
    main()

