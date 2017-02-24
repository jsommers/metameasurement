from abc import abstractmethod
from subprocess import Popen, PIPE, STDOUT, run
from time import sleep, time
import re

from switchyard.lib.userlib import *


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
    def parse(completed_process):
        loadm = TopCommandParser._loadre.search(completed_process.stdout)
        loadvals = tuple(map(float, loadm.groups()))
        cpum = TopCommandParser._cpure.search(completed_process.stdout)
        cpuvals = tuple(map(float, cpum.groups()))
        return dict(zip(TopCommandParser._keys, loadvals+cpuvals))


class IostatCommandParser(ObservationParser):
    command = "iostat -d -K"
    _keys = ('KB/t','tps','MB/s')

    @staticmethod
    def parse(completed_process):
        # first line shows name of each device
        # second line shows headers for each device
        # third line are device stats
        s = completed_process.stdout.split('\n')
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
    def parse(completed_process):
        s = completed_process.stdout.split('\n')[1]
        keys = [ '_'.join((NetstatIfaceStatsCommandParser._iface, k)) for k in NetstatIfaceStatsCommandParser._keys ]
        return dict(zip(keys, map(int, s.split()[4:])))


class SystemObserver(object):
    def __init__(self, parser):
        self._results = []
        self._parser = parser

    def __call__(self):
        now = time()
        completed_proc = run(self._parser.command, shell=True, 
            universal_newlines=True, stdout=PIPE, stderr=STDOUT)
        if completed_proc.returncode==0:
            self._results.append( (now, self._parser.parse(completed_proc)) )
        else:
            self._results.append( (now, {'error':completed_proc.stdout}) )

    def results(self):
        return self._results


        #lsof1 = "lsof -S 3 -n -p {}"
        #lsof2 = "lsof -S 3 -n -i UDP -i TCP"
        #lsof3 = "lsof -S 3 -n | grep ICMP"
        # vm_stat
        # vmmap (root required)

if __name__ == '__main__':
    x = SystemObserver(TopCommandParser)
    x()
    print(x.results())

    y = SystemObserver(IostatCommandParser)
    y()
    print(y.results())

    z = SystemObserver(NetstatIfaceStatsCommandParser('en0'))
    z()
    print(z.results())
