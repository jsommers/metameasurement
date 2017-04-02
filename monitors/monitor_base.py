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
from enum import Enum

from numpy import min_scalar_type, iinfo

def _periodic_observer(interval):
    interval = float(interval)
    return lambda: random.uniform(interval, interval)

def _gamma_observer(probe_rate):
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
    return lambda: random.gammavariate(shape,1/desired_scale)

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


#def sig_catch(*args):
#    for t in asyncio.Task.all_tasks():
#        t.cancel()
#    asyncio.get_event_loop().call_later(0.5, stop_world)
#
#def stop_world():
#    asyncio.get_event_loop().stop()
#
#
#if __name__ == '__main__':
#    loop = asyncio.get_event_loop()
#    loop.add_signal_handler(signal.SIGINT, sig_catch)
#
#    cpu = SystemObserver(CPUDataSource(), lambda: random.expovariate(1.0))
#    f1 = asyncio.ensure_future(cpu())
#
#    io = SystemObserver(IODataSource(), lambda: random.uniform(2.0,2.0))
#    f2 = asyncio.ensure_future(io())
#
#    net = SystemObserver(NetIfDataSource('en0'), lambda: random.uniform(2.0, 2.0))
#    f3 = asyncio.ensure_future(net())
#
#    mem = SystemObserver(MemoryDataSource(), lambda: random.uniform(2.0, 2.0))
#    f4 = asyncio.ensure_future(mem())
#
#    try:
#        loop.run_forever()
#    except:
#        pass
#    finally:
#        loop.close()
#
#    from statistics import mean, stdev, median, variance
#
#    print(cpu.results.all())
#    print(io.results.all())
#    print(net.results.all())
#    print(mem.results.summary(max))
#    print(net.results.compute(max, 'en0_dropin'))
#    print(mem.results.compute(mean, 'percent'))
