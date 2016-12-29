from switchyard.lib.userlib import *


class MeasurementObserver(object):
    def __init__(self, net, *args, **kwargs):
        self._net = net

    def run(self):
        pass


def main(net, *args, **kwargs):
    m = MeasurementObserver(net)
    m.run()
    net.shutdown()
