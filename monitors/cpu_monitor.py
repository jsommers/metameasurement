from statistics import mean
import logging

from psutil import cpu_times_percent
from monitor_base import DataSource, SystemObserver, ResultsContainer, \
    _periodic_observer, ConfigurationError

class CPUDataSource(DataSource):
    '''
    Monitor CPU usage (via psutil module)
    '''
    def __init__(self):
        DataSource.__init__(self)
        self._results = ResultsContainer()
        cpulist = cpu_times_percent(percpu=True) # as per psutil docs: first call gives rubbish 
        self._log = logging.getLogger('mm')
        x = cpulist.pop(0)
        self._keys = [ a for a in dir(x) if not a.startswith('_') and \
            not callable(getattr(x,a)) ]

    def __call__(self):
        sample = cpu_times_percent(percpu=True)
        result = { "cpu{}_{}".format(i,k):getattr(sample[i],k) for i in range(len(sample)) \
            for k in self._keys }
        result['idle'] = mean([ getattr(x, 'idle') for x in sample ])
        self._results.add_result(result)

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
    interval = configdict.pop('interval', 1)
    if len(configdict):
        raise ConfigurationError('Unrecognized configuration parameters: {}'.format(configdict))

    return SystemObserver(CPUDataSource(), _periodic_observer(interval))
