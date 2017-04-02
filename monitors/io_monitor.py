from psutil import disk_io_counters
from monitor_base import SystemObserver, DataSource, _compute_diff_with_wrap, _periodic_observer

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


def create(config):
    # could pass in list of devices that we want to monitor.
    # for now, just monitor all
    return SystemObserver(IODataSource(), _periodic_observer(config.get('interval', 1)))

