from psutil import cpu_times_percent
from monitor_base import DataSource, SystemObserver, _periodic_observer

class CPUDataSource(DataSource):
    '''
    Monitor CPU usage (via psutil module)
    '''
    def __init__(self):
        DataSource.__init__(self)
        x = cpu_times_percent() # as per psutil docs: first call will give rubbish 
        self._keys = [ a for a in dir(x) if not a.startswith('_') and \
            not callable(getattr(x,a)) ]

    def __call__(self):
        sample = cpu_times_percent()
        return { k:getattr(sample,k) for k in self._keys }


def create(configdict):
    return SystemObserver(CPUDataSource(), _periodic_observer(configdict.get('interval', 1)))
