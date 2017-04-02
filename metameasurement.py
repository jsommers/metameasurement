import sys
import asyncio
import signal
import os
import re
from time import time, strftime, gmtime
import logging
from statistics import mean, stdev
import argparse
import subprocess
import json
import random
import importlib

VERSION = '2017.4.1'

class MetadataOrchestrator(object):
    def __init__(self, debug, quiet, fileprefix, 
                 logfile=False, statusinterval=5):
        self._asyncloop = asyncio.SelectorEventLoop()
        asyncio.set_event_loop(self._asyncloop)
        self._asyncloop.add_signal_handler(signal.SIGINT, self._sig_catcher)
        self._asyncloop.add_signal_handler(signal.SIGTERM, self._sig_catcher)
        self._debug = debug
        self._quiet = quiet
        self._update_interval = statusinterval
        self._log = logging.getLogger('mm')
        self._monitors = {}
        self._done = False
        self._warmcooltime = 2
        self._fileprefix = fileprefix
        self._toolproc = None
        self._starttime = time()
        self._metadict = {}

        logconfig = {
            'format':'%(asctime)s | %(name)s | %(levelname)s | %(message)s',
            'level':logging.INFO,
        }

        if quiet:
            logconfig['level'] = logging.WARNING
            self._log.setLevel(logging.WARNING)
        elif self._debug:
            logconfig['level'] = logging.DEBUG
            self._asyncloop.set_debug(True)
        else:
            self._log.setLevel(logging.INFO)

        if logfile:
            logconfig['filename'] = self._make_filebase() + '.log'
            logconfig['filemode'] = 'w'
            
        logging.basicConfig(**logconfig)

    def add_metadata(self, key, obj):
        self._metadict[key] = obj

    def add_monitor(self, name, sysobserver):
        self._monitors[name] = sysobserver
        sysobserver.setup(self)
        asyncio.ensure_future(sysobserver())

    @property
    def monitors(self):
        return list(self._monitors.keys())

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

        with open("{}.json".format(self._make_filebase()), 'w') as outfile:
            json.dump(self._metadict, outfile)

    def _make_filebase(self):
        timestr = strftime("%Y%m%d_%H%M%S", gmtime(self._starttime))
        return "{}_{}".format(self._fileprefix, timestr)

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
        create = asyncio.create_subprocess_shell(commandline, \
                                                 stdout=asyncio.subprocess.PIPE,\
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

    async def _running_status(self):
        while True:
            try:
                await asyncio.sleep(self._update_interval)
            except asyncio.CancelledError:
                break
            idlecpu = self._monitors['cpu'].results.last_result('idle')
            self._log.info("Idle CPU {}".format(idlecpu))

    def run(self, commandline):
        self._log.info("Starting metadata measurement with verbose {} and commandline <{}>".format(
            self._debug, commandline))

        self._toolfut = asyncio.Future()
        self._cmdstart = self._asyncloop.call_later(self._warmcooltime,
            self._start_tool, commandline)

        if not self._quiet and 'cpu' in self._monitors:
            asyncio.ensure_future(self._running_status())

        try:
            self._asyncloop.run_forever()
        finally:
            self._asyncloop.close()

        self._endtime = time()
        self._write_meta(commandline)

def _probe_monitors():
    monlist = []
    for m in os.listdir('monitors'):
        mobj = re.match('(?P<mon>\w+)_monitor.py', m)
        if mobj:
            monlist.append(mobj.group('mon'))
    return monlist

monlist = _probe_monitors()

def _check_monitor_arg(s):
    monarg = s.split(':')
    if not monarg or monarg[0] not in monlist:
        msg = "{} does not start with a valid monitor name (followed by an optional : and configuration arguments).  ".format(s)
        msg += "Valid monitor names are: {}".format(','.join(monlist))
        raise argparse.ArgumentTypeError(msg)
    parmdict = {}
    for m in monarg[1:]:
        if '=' in m:
            k,v = m.split('=')
            parmdict[k] = v
        else:
            parmdict[m] = True
    return (monarg[0], parmdict)


def _load_monitor(mname, mconfig):
    sys.path.append(os.path.abspath('monitors'))
    m = importlib.__import__("{}_monitor".format(mname))
    return m.create(mconfig)


def main():
    parser = argparse.ArgumentParser(
            description='Automatic generation of active measurement metadata')
    parser.add_argument('-d', '-v', '--verbose', '--debug',
                        dest='verbose', action='store_true', default=False,
                        help='Turn on verbose/debug output.')
    parser.add_argument('-f', '--fileprefix', dest='fileprefix', type=str, 
                        default='metadata', metavar='FILE_PREFIX',
                        help='Prefix for filename that includes metadata for '
                             'a given run.  default="metadata".')
    parser.add_argument('-l', '--logfile', dest='logfile', default=False,
                        action='store_true', 
                        help='Write log entries to a file (with a similar '
                             'file name as metadata).  '
                             'default=only write to stdout.')
    parser.add_argument('-c', '--command', dest='commandline', 
                        type=str, default='sleep 5',
                        help='The full command line for running an active '
                             'measurement tool (note that the command line '
                             'almost certainly needs to be quoted). '
                             'default="sleep 5".')
    parser.add_argument('-q', '--quiet', dest='quiet', action='store_true',
                        default=False,
                        help='Turn off all info (and below) log messages')
    parser.add_argument('-u', '--status', dest='statusinterval', type=int,
                        default=5,
                        help='Time interval on which to show periodic '
                             'status while running.  default=5 sec.')
    parser.add_argument('-M', '--monitor', dest='monitors', 
                        type=_check_monitor_arg,
                        action='append',
                        help='Select monitors to include.  Default=None. '
                        'Valid monitors={}'.format(','.join(monlist)))
    args = parser.parse_args()

    m = MetadataOrchestrator(args.verbose, args.quiet, args.fileprefix, args.logfile, args.statusinterval)
    if not args.monitors:
        print("No monitors configured.  Must specify at least one -M option.", file=sys.stderr)
        print("Valid monitors: {}\n".format(','.join(monlist)))
        parser.print_usage()
        return

    for monname,monconfig in args.monitors:
        m.add_monitor(monname, _load_monitor(monname, monconfig))

    m.run(args.commandline)

if __name__ == '__main__':
    main()

