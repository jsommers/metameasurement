#!/bin/bash -x

INTF=eth0
DEST=10.0.1.1
DURATION=3600

# all with default 1s sampling interval, or avg 1 probe/sec
python3 metameasurement.py -Mcpu -c "sleep $DURATION" -f overhead_1hcpuonly -l
#python3 metameasurement.py -Mmem -c "sleep $DURATION" -f overhead_1hmemonly -l
#python3 metameasurement.py -Mio -c "sleep $DURATION" -f overhead_1hioonly -l
#python3 metameasurement.py -Mnetstat -c "sleep $DURATION" -f overhead_1hnetstatonly -l
python3 metameasurement.py -Mrtt:interface=$INTF:type=ping:dest=$DEST -c "sleep $DURATION" -f overhead_1hrttonly -l
python3 metameasurement.py -Mcpu -Mmem -Mio -Mnetstat -Mrtt:interface=$INTF:type=ping:dest=$DEST -c "sleep $DURATION" -f overhead_1hallmon -l
