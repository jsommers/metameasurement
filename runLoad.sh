compileFlag=$1
# This needs to be run for the first time
# Note down the following two values
# Number of loops for 100% CPUness: 376 (-c flag)
# Number of loops for 100% Memory-ness: 47 (-m flag)
if [[ $compileFlag -eq "1" ]]; then
    make -C ./wilee
    echo "Calibrating wilee..."
    ./wilee/wileE --calibrate
fi

if [[ $compileFlag -eq "0" ]]; then
    python loadmeta.py -d gamma -s 2 -e 2 -w 5 -c 376 -m 47 -C 0.0 -M 0.0 -N
fi
