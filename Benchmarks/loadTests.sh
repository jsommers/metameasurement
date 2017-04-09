#!/usr/bin/env bash -x

# NB: assumes that the runLoad script has been properly, e.g., runtime
# number of cores, other parameters.

# NB: assumes that pyvenv is sourced correctly into current shell 
# when this is executed

DURATION="3600"
INTF="eth0"
TARGET="10.0.1.1"
SLEEP="300"

# expt with artificial cpu load
./LoadGenerator/runLoad.sh c &
python3 metameasurement.py -Mcpu -Mmem -Mio -Mnetstat -Mrtt:interface=$INTF:type=ping:dest=$TARGET -c "sleep $DURATION" -f load_1h_cpuload -l
killall python3
sleep $SLEEP

# expt with artificial mem load
./LoadGenerator/runLoad.sh m &
python3 metameasurement.py -Mcpu -Mmem -Mio -Mnetstat -Mrtt:interface=$INTF:type=ping:dest=$TARGET -c "sleep $DURATION" -f load_1h_memload -l 
killall python3
sleep $SLEEP

# expt with artificial disk/io load
./LoadGenerator/runLoad.sh m &
python3 metameasurement.py -Mcpu -Mmem -Mio -Mnetstat -Mrtt:interface=$INTF:type=ping:dest=$TARGET -c "sleep $DURATION" -f load_1h_ioload -l 
killall python3
sleep $SLEEP

