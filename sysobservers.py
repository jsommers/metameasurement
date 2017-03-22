from abc import abstractmethod
import asyncio
from time import sleep, time
import re
import signal
from psutil import cpu_times_percent, disk_io_counters, \
    net_io_counters, virtual_memory
from numpy import min_scalar_type, iinfo
import random

__all__ = ['CPUDataSource', 'IODataSource', 'NetIfDataSource', 
    'MemoryDataSource', 'SystemObserver', 'ResultsContainer']


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
    containing a data observation.
    '''
    @abstractmethod
    def __call__(self):
        '''
        Should return a dictionary with keyword:value observations.
        '''
        raise NotImplementedError()


class CPUDataSource(DataSource):
    '''
    Monitor CPU usage (via psutil module)
    '''
    def __init__(self):
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
        return fn([ t[1][key] for t in self._results[-lastn:] ])

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
        self._results.pop(0)


class SystemObserver(object):
    def __init__(self, datasource, intervalfn, dropfirst=True):
        self._source = datasource
        self._results = ResultsContainer()
        self._done = False
        assert(callable(intervalfn))
        self._intervalfn = intervalfn
        self._dropfirst = dropfirst # for psutil data, best to drop the first measurement

    async def __call__(self):
        while True:
            sample = self._source()
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
