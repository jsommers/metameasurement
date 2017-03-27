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
    # run this for CPU and RAM load
    # -C is maximum CPUness
    # -M is maximum RAMness
    # python 3 loadmeta.py -f gamma -s 2 -e 2 -w 5 \
    #                      -c 376 -m 47 \
    #                      -C 1.0 -M 0.0

    # run this for disk load
    # python3 loadmeta.py -f gamma -s 2 -e 2 -w 5 \
    #                     -c 376 -m 47 -d 1000 \
    #                     -C 0.0 -M 0.0 -D

    # run this for network load
    # remember to start iPerf server with "iperf3 -s"
    python3 loadmeta.py -f gamma -s 2 -e 2 -w 5 \
                        -c 376 -m 47 -n 2\
                        -C 0.0 -M 0.0 -N -i "127.0.0.1"
fi
