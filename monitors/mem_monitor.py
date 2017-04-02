from psutil import virtual_memory
from monitor_base import DataSource, _periodic_observer, SystemObserver

class MemoryDataSource(DataSource):
    '''
    Monitor memory usage via psutil.
    '''
    def __init__(self):
        DataSource.__init__(self)
        x = virtual_memory() # as per psutil docs: first call will give rubbish 
        self._keys = [ a for a in dir(x) if not a.startswith('_') and \
            not callable(getattr(x,a)) ]

    def __call__(self):
        sample = virtual_memory()
        return dict([ (k,getattr(sample,k)) for k in self._keys ]) 


def create(config):
    return SystemObserver(MemoryDataSource(), _periodic_observer(config.get('interval', 1)))
