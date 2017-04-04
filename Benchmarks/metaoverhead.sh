#!/bin/bash -x

# all with default 1s sampling interval, or avg 1 probe/sec
python3 metameasurement.py -Mcpu -c "sleep 3600" -f overhead_1hcpuonly -l
python3 metameasurement.py -Mmem -c "sleep 3600" -f overhead_1hmemonly -l
python3 metameasurement.py -Mio -c "sleep 3600" -f overhead_1hioonly -l
python3 metameasurement.py -Mnetstat -c "sleep 3600" -f overhead_1hnetstatonly -l
python3 metameasurement.py -Mrtt:interface=eth0 -c "sleep 3600" -f overhead_1hrttonly -l
python3 metameasurement.py -Mcpu -Mmem -Mio -Mnetstat -Mrtt:interface=eth0 -c "sleep 3600" -f overhead_1hallmon -l
