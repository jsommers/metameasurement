#!/usr/bin/env bash

# This needs to be run for the first time
# Note down the following two values
# Number of loops for 100% CPUness: 376 (-c flag)
# Number of loops for 100% Memory-ness: 47 (-m flag)

if [[ ! -r calib_results.txt ]]; then
    echo "No calibration data found; running calibration"
    CALIBRATE=1
fi

if [[ ! -r ./wilee/wileE ]]; then
    make -C ./wilee
fi

if [[ $CALIBRATE -eq "1" ]]; then
    echo "Calibrating wilee..."
    ./wilee/wileE --calibrate | tee calib_results.txt
fi

CPUMEMOPTS=`fgrep -v '#' calib_results.txt | perl -pe 's/\n/ /'`
# echo "opts: $CPUMEMOPTS"

ACTION=$1
if [[ -z $ACTION ]]; then
    echo "Usage: $0 <action>, where action=c, m, d, or n (cpu, mem, disk, network)"
    exit
fi

WAIT="-w2"
ONOFF="-Fconstant -s60 -e60"
CORES="-x1"
RUNTIME="-t 240"
NETLOADARGS="-i 10.100.100.2 -N -n 1G"
NETPREFIX='' # ssh, if necessary

if [[ $ACTION == "c" ]]; then
    # -C is maximum CPUness
    python3 loadmeta.py $ONOFF $WAIT $CPUMEMOPTS -C 1.0 -M 0.0 $CORES $RUNTIME
elif [[ $ACTION == "m" ]]; then
    # -M is maximum RAMness
    python3 loadmeta.py $ONOFF $WAIT $CPUMEMOPTS -C 0.0 -M 1.0 $CORES $RUNTIME
elif [[ $ACTION == "d" ]]; then
    # run this for disk load
    python3 loadmeta.py $ONOFF $WAIT -D -d 1000 -f /home/pi/XXX $RUNTIME
    rm -f /home/pi/XXX
elif [[ $ACTION == "n" ]]; then
    # run this for network load
    # remember to start iPerf server with "iperf3 -s"
    python3 loadmeta.py $ONOFF $WAIT -I '$NETPREFIX' $NETLOADARGS $RUNTIME
else 
    echo "Invalid action $ACTION"
    echo "Specify c (cpu), m (mem), d (disk), or n (network)"
fi

killall wileE  2>/dev/null #kill any runaway wileE processes
