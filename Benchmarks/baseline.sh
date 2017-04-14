#!/bin/bash -x

INTF=eth0
DEST=10.0.1.1
DURATION=3600
CPUAFF="-C0"

# all with default 1s sampling interval, or avg 1 probe/sec
python3 metameasurement.py $CPUAFF -Mcpu -c "sleep $DURATION" -F overhead_1hcpuonly -l
#python3 metameasurement.py $CPUAFF -Mmem -c "sleep $DURATION" -F overhead_1hmemonly -l
#python3 metameasurement.py $CPUAFF -Mio -c "sleep $DURATION" -F overhead_1hioonly -l
#python3 metameasurement.py $CPUAFF -Mnetstat -c "sleep $DURATION" -F overhead_1hnetstatonly -l
python3 metameasurement.py $CPUAFF -Mrtt:interface=$INTF:type=ping:dest=$DEST -c "sleep $DURATION" -F overhead_1hrttonly -l
python3 metameasurement.py $CPUAFF -Mcpu -Mmem -Mio -Mnetstat -Mrtt:interface=$INTF:type=ping:dest=$DEST -c "sleep $DURATION" -F overhead_1hallmon -l
