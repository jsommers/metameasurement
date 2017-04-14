import logging
from statistics import mean

from psutil import virtual_memory
from monitor_base import DataSource, _periodic_observer, SystemObserver, \
    ResultsContainer, ConfigurationError

class MemoryDataSource(DataSource):
    '''
    Monitor memory usage via psutil.
    '''
    def __init__(self):
        DataSource.__init__(self)
        x = virtual_memory() # as per psutil docs: first call will give rubbish 
        self._keys = [ a for a in dir(x) if not a.startswith('_') and \
            not callable(getattr(x,a)) ]
        self._results = ResultsContainer()
        self._log = logging.getLogger('mm')

    def __call__(self):
        sample = virtual_memory()
        self._results.add_result(dict([ (k,getattr(sample,k)) for k in self._keys ]))

    @property
    def name(self):
        return 'mem'

    def metadata(self):
        self._results.drop_first()
        self._log.info("Mem summary: {}".format(self._results.summary(mean)))
        return self._results.all()

    def show_status(self):
        pass


def create(configdict):
    interval = configdict.pop('interval', 1)
    if len(configdict):
        raise ConfigurationError('Unrecognized configuration parameter: {}'.format(configdict))

    return SystemObserver(MemoryDataSource(), _periodic_observer(interval))
