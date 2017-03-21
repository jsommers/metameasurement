from abc import abstractmethod
import asyncio
from time import sleep, time
import re
import signal

from switchyard.lib.userlib import *

__all__ = ['TopCommandParser', 'IostatCommandParser', 'NetstatIfaceStatsCommandParser', 
    'SystemObserver', 'ResultsContainer']

class ObservationParser(object):
    '''
    A command + parser for some system tool from which host performance
    measures can be gathered, e.g., lsof, iostat, top, uptime, etc.
    In addition to defining a parse function, should define a class-level
    command attribute with the command to execute.  The command should be
    one that can be passed directly to the shell for execution.
    '''

    @staticmethod
    @abstractmethod
    def parse(completed_process):
        '''
        Takes a completed_process argument (see subprocess library
        documentation).

        Should return a dictionary with keyword:value observations.
        '''
        raise NotImplementedError()


class TopCommandParser(ObservationParser):
    command = 'top -l1|head -4|tail -2'
    _loadre = re.compile('Load Avg:\s*([\.\d]+),\s*([\.\d]+),\s*([\.\d]+)')
    _cpure = re.compile('CPU usage:\s*([\.\d]+)%\s*user,\s+([\.\d]+)%\s*sys,\s+([\.\d]+)%\s*idle')
    _keys = ('load1min','load5min','load15min','cpuuser','cpusys','cpuidle')

    @staticmethod
    def parse(output):
        loadm = TopCommandParser._loadre.search(output)
        loadvals = tuple(map(float, loadm.groups()))
        cpum = TopCommandParser._cpure.search(output)
        cpuvals = tuple(map(float, cpum.groups()))
        return dict(zip(TopCommandParser._keys, loadvals+cpuvals))


class IostatCommandParser(ObservationParser):
    command = "iostat -d -K"
    _keys = ('KB/t','tps','MB/s')

    @staticmethod
    def parse(output):
        # first line shows name of each device
        # second line shows headers for each device
        # third line are device stats
        s = output.split('\n')
        devices = s[0].split()
        stats = map(float, s[2].split())
        keys = ['_'.join((d,sk)) for sk in IostatCommandParser._keys \
            for d in devices ]
        return dict(zip(keys, stats))

class NetstatIfaceStatsCommandParser(ObservationParser):
    command = "netstat -I {} -d"
    _keys = ('ipkts','ierrs','opkts','oerrs','coll','drop')
    _iface = ''

    def __init__(self, iface):
        NetstatIfaceStatsCommandParser._iface = iface
        NetstatIfaceStatsCommandParser.command = \
            NetstatIfaceStatsCommandParser.command.format(iface)

    @staticmethod
    def parse(output):
        s = output.split('\n')[1]
        keys = [ '_'.join((NetstatIfaceStatsCommandParser._iface, k)) for k in NetstatIfaceStatsCommandParser._keys ]
        return dict(zip(keys, map(int, s.split()[4:])))


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

    def compute_stat(self, fn, key, lastn=0):
        if not self._results:
            return None
        return fn([ t[1][key] for t in self._results[-lastn:] ])

    def summary(self, fn):
        if not self._results:
            return None
        klist = list(self._results[0][1].keys())
        vlist = [ self.compute_stat(fn, k) for k in klist ]
        return dict(zip(klist,vlist))

    def __str__(self):
        return str(self.summary(mean))

    def __repr__(self):
        return repr(self.summary(mean))

    def all(self):
        return self._results


class SystemObserver(object):
    def __init__(self, parser, interval=1.0):
        self._parser = parser
        self._results = ResultsContainer()
        self._done = False
        self._interval = interval

    async def __call__(self):
        while True:
            create = asyncio.create_subprocess_shell(self._parser.command, 
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT)
            try:
                proc = await create
            except asyncio.CancelledError:
                break
            try:
                stdout,stderr = await proc.communicate()
            except asyncio.CancelledError:
                break
            stdout = stdout.decode('utf8')

            if proc.returncode==0:
                self._results.add_result(self._parser.parse(stdout))
            else:
                self._results.add_result({'error':stdout})

            if self._done:
                break

            if asyncio.Task.current_task().cancelled():
                break
            try:
                await asyncio.sleep(self._interval)
            except asyncio.CancelledError:
                break

    def stop(self):
        self._done = True

    def set_interval(self, i):
        self._interval = i

    @property
    def results(self):
        return self._results

#class LsofCommandParser(ObservationParser):
        #lsof1 = "lsof -S 3 -n -p {}"
        #lsof2 = "lsof -S 3 -n -i UDP -i TCP"
        #lsof3 = "lsof -S 3 -n | grep ICMP"
        # vm_stat
        # vmmap (root required)

def sig_catch(*args):
    asyncio.get_event_loop().stop()

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGINT, sig_catch)

    #x = SystemObserver(TopCommandParser)
    #f = asyncio.ensure_future(x())

    #y = SystemObserver(IostatCommandParser)
    #f = asyncio.ensure_future(y())

    z = SystemObserver(NetstatIfaceStatsCommandParser('en0'))
    f = asyncio.ensure_future(z())

    try:
        loop.run_forever()
    except:
        pass
    finally:
        print("here we are...")
        f.cancel()
        loop.close()

    from statistics import mean, stdev, median, variance

    #print(x.results)
    #print(x.results.last_result('cpuidle'))
    #print(x.results.compute_stat(mean, 'cpuidle', 2))
    #print(x.results.compute_stat(mean, 'cpuidle'))
    #print(x.results.compute_stat(median, 'cpuidle'))

    print(z.results.all())
