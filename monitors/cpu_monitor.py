from statistics import mean
import logging

from psutil import cpu_times_percent
from monitor_base import DataSource, SystemObserver, ResultsContainer, _periodic_observer

class CPUDataSource(DataSource):
    '''
    Monitor CPU usage (via psutil module)
    '''
    def __init__(self):
        DataSource.__init__(self)
        self._results = ResultsContainer()
        x = cpu_times_percent() # as per psutil docs: first call will give rubbish 
        self._log = logging.getLogger('mm')
        self._keys = [ a for a in dir(x) if not a.startswith('_') and \
            not callable(getattr(x,a)) ]

    def __call__(self):
        sample = cpu_times_percent()
        self._results.add_result({ k:getattr(sample,k) for k in self._keys })

    @property
    def name(self):
        return 'cpu'

    def metadata(self):
        self._results.drop_first()
        self._log.info("CPU summary: {}".format(self._results.summary(mean)))
        return self._results.all()

    def show_status(self):
        self._log.info("CPU idle: {}".format(self._results.last_result('idle')))


def create(configdict):
    return SystemObserver(CPUDataSource(), _periodic_observer(configdict.get('interval', 1)))
