from psutil import net_io_counters
from monitor_base import DataSource, _compute_diff_with_wrap


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
