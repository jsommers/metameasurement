import sys
from abc import abstractmethod, abstractproperty
import asyncio
from time import time
import re
import socket
import signal
import logging
import functools
import random
import os
from math import isinf
from enum import Enum

#from numpy import min_scalar_type, iinfo

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
    probe_rate = float(probe_rate)
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
    bits = last.bit_length()
    if bits <= 16:
        dtypemax = 2**16-1
    elif bits <= 32:
        dtypemax = 2**32-1
    else:
        dtypemax = 2**64-1
    #dtype = min_scalar_type(last)
    #dtypemax = iinfo(dtype).max
    return curr + (dtypemax - last)


class ConfigurationError(Exception):
    pass


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
        Should not return anything.
        '''
        raise NotImplementedError()

    @abstractmethod
    def metadata(self):
        '''
        Return metadata from the data source.  Can be any Python data type that
        can be serialized to json.
        '''
        pass

    def cleanup(self):
        pass

    @abstractproperty
    def name(self):
        pass

    def stop(self):
        self._done = True

    @abstractmethod
    def show_status(self):
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
        data = [ t[1][key] for t in self._results[-lastn:] if not isinf(t[1][key]) ]
        if not data:
            return None
        return fn(data)

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
    def __init__(self, datasource, intervalfn):
        self._source = datasource
        self._done = False
        assert(callable(intervalfn))
        self._intervalfn = intervalfn
        self._log = logging.getLogger('mm')

    async def __call__(self):
        evl = asyncio.get_event_loop()
        compensate = 0

        # stagger startup, randomly over 1sec
        try:
            await asyncio.sleep(random.random())
        except asyncio.CancelledError:
            return

        while True:
            # call the data source to take a sample
            self._source()

            if self._done or \
                asyncio.Task.current_task().cancelled():
                break

            before = evl.time()
            sleeptime = self._intervalfn()
            try:
                await asyncio.sleep(sleeptime)
            except asyncio.CancelledError:
                break
            actualsleep = evl.time() - before 
            if actualsleep > sleeptime*1.5:
                self._log.warn("Monitor {} slept too long (wanted {:.3f} but got {:.3f}".format(self._source.__class__.__name__, sleeptime, actualsleep))

    def stop(self):
        self._done = True
        self._source.stop()
        asyncio.get_event_loop().call_soon(self._source.cleanup)

    def set_intervalfn(self, fn):
        assert(callable(fn))
        self._intervalfn = fn

    @property
    def source(self):
        return self._source

    def metadata(self):
        return self._source.metadata()

