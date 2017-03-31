
Try it out
----------

Requires Python 3.6.

A basic recipe for running the tool::

    # Install a python venv and required modules
    python3 -m venv xenv
    source xenv/bin/activate
    pip3 install -r requirements

    # Give a test run (may require running as root)
    # By default, the tool runs "sleep 5" as the external "measurement" process, which will take ~7/8 seconds to finish.
    python3 metameasurement.py

    # Tool has the following options
    -C, --cpu
            Specifies the desired CPUness

Plotting tool::
    # use -i to plot individial items
    # use -g to plot all items in a group
    # use -a to plot all items in all groups
    # see what metadata can be plotted without any arguments
    python3 plotmeta.py -i monitors:rtt:icmprtt -i monitors:rtt:seq -i monitors:cpu:idle <json file produced by previous step>
    python3 plotmeta.py -g rtt <json file produced by previous step>
    python3 plotmeta.py -a <json file produced by previous step>
    python3 plotmeta.py <json file produced by previous step>

    # use a different external measurement tool
    python3 metameasurement.py -c "ping -c 100 www.google.com" 

For generating artificial load::

    # loadmeta.py can be used to generate artificial CPU, RAM, disk and network loads
    # CPU and RAM loads are generated using wileE benchmark
    # disk load with dd is used
    # network load is generated using with iPerf (so, the tool assumes that iPerf3 is installed)
    # loads are called in on and off phases and there is also a wait time
    # loads are generated during on phases using different distributions (gamma, exponential)

    # Configuration
    # to configure wileE for the first time, use ./runLoad.sh 1
    # wilee calibrates the number of loops required to achieve 100% CPU and RAM loads
    # once the values are found, set them to -c and -m flags
    # use -s to set duration of on phase
    # use -e to set duration of off phase
    # use -w to set wait period before starting the tool
    # use -C to set the percentage of CPU load needed
    # use -M to set the percentage of RAM load needed
    # use -D to start disk load
    # use -d to set the max count of disks blocks to write
    # use -N to start network load
    # use -n to denote max bandwidth allowed
    # use -i to set iPerf server's address

    # Examples
    # to run 100% CPU load
    python3 loadmeta.py -f gamma -s 2 -e 2 -w 5 -c 376 -m 47 -C 1.0 -M 0.0
    # to run 100% memory load
    python3 loadmeta.py -f gamma -s 2 -e 2 -w 5 -c 376 -m 47 -C 0.0 -M 1.0
    # to run disk load
    python3 loadmeta.py -f gamma -s 2 -e 2 -w 5 -d 1000 -D
    # to run network load
    python3 loadmeta.py -f gamma -s 2 -e 2 -w 5 -n 2 -N -i "127.0.0.1"
