from statistics import mean
import logging

from psutil import disk_io_counters
from monitor_base import SystemObserver, DataSource, ResultsContainer, \
    _compute_diff_with_wrap, _periodic_observer, ConfigurationError

class IODataSource(DataSource):
    '''
    Monitor disk IO counters via psutil.  The psutil call just yields the current
    counter values; internally we keep last sample and only store differences.
    '''
    def __init__(self):
        DataSource.__init__(self)
        x = self._lastsample = disk_io_counters(perdisk=True) # as per psutil docs: first call will give rubbish 
        self._disks = x.keys()
        self._results = ResultsContainer()
        self._log = logging.getLogger('mm')
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
        self._results.add_result(rd)

    @property
    def name(self):
        return 'io'

    def metadata(self):
        self._results.drop_first()
        self._log.info("IO summary: {}".format(self._results.summary(mean)))
        return self._results.all()

    def show_status(self):
        pass


def create(configdict):
    # could pass in list of devices that we want to monitor.
    # for now, just monitor all
    interval = configdict.pop('interval', 1)
    if len(configdict):
        raise ConfigurationError('Unrecognized configuration parameters: {}'.format(configdict))

    return SystemObserver(IODataSource(), _periodic_observer(interval))
