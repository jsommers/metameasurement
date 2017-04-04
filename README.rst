
Try it out
----------

Requires Python 3.6.

A basic recipe for running the tool::

    # Install a python venv and required modules
    python3 -m venv xenv
    source xenv/bin/activate
    pip3 install -r requirements

    # Give a test run (may require running as root)
    # By default, the tool runs "sleep 5" as the external "measurement" process.
    # This which will take ~7/8 seconds to finish.
    python3 metameasurement.py

    # Tool has the following options
    -d, -v, --verbose, --debug
            Turn on verbose/debug output.
    -f, --fileprefix
            Prefix for filename that includes metadata for a given run.
    -l, --logfile
            Send log messages to a file (instead of stdout).
    -c, --command
            The full command line for running an active measurement tool. 
            Command should be enclosed within quotes (e.g., "ping -c 1 test.com")
    -u, --statusinterval
            Time interval on which to show periodic status while running.
    -q, --quiet
            Turn off all info, log and status messages.
    -M, --monitor
            Add a metadata monitoring source.
            Standard available sources include cpu,mem,io,netstat,rtt
              (see monitors/ directory)

            To configure a monitor, parameters may be specified along
            with each monitor name, each separated by a colon (':').
            Each parameter may be a single string, or a key=value.
            The order of parameters doesn't matter.

            Valid parameters for each standard monitor are:

                -M cpu:interval=X  --- set the periodic sampling interval
                                       (default = 1sec)
                -M io:interval=X   --- set the periodic sampling interval.
                -M mem:interval=X  --- set the periodic sampling interval.
                -M netstat:interval=X  
                                   --- set the periodic sampling interval.
                           Additional string arguments to the netstat monitor
                           can specify interface names to monitor (all
                           interfaces are included if none are specified).
                           For example, to monitor en0's netstat counters
                           every 5 seconds:
                           -M netstat:interval=5:en0
                -M rtt:interface=IfaceName:rate=R:dest=D:type=ProbeType:maxttl=MaxTTL:proto=Protocol:allhops
                           Monitor RTT along a path to destination D 
                           out of interface IfaceName with probe rate R.
                           Probe interval is gamma distributed.
                           Default dest D = 8.8.8.8.
                           Default rate R = 1/sec.
                           ProbeType = ping | hoplimited (default=hoplimited)
                           MaxTTL = maximum ttl (for hop-limited probes)
                                    default value = 1
                           Protocol = (icmp | tcp | udp) (for hop-limited probes)
                                    default = icmp
                           allhops = probe all hops up to maxttl (for hop-limited probes)


    # Examples
    # Use a different external measurement tool
    python3 metameasurement.py -Mcpu "ping -c 100 www.google.com" 
    # Monitor CPU only for traceroute
    python3 metameasurement.py -Mcpu "traceroute www.google.com" 
    # Monitor IO and Netstat counters only for ping
    python3 metameasurement.py -Mio -Mnetstat -c "ping www.google.com" 

    # Output
    # Running the tool produces a json file with captured metadata.

Plotting tool::

    # Simple tool to plot all the metadata collected.
    # See what metadata can be plotted without any arguments.
    python3 plotmeta.py <json file produced by previous step>

    # Tool has the following options
    -i, --item
            Include individual item in the plot, e.g., monitors:cpu:idle.
    -g, --group
            Include a group of items in the plot, e.g., rtt includes icmprtt and seq/
    -a, --all
            Plot all groups in separate subplots.

    # Examples
    python3 plotmeta.py -i monitors:rtt:icmprtt -i monitors:rtt:seq -i monitors:cpu:idle <json file produced by previous step>
    python3 plotmeta.py -g rtt <json file produced by previous step>
    python3 plotmeta.py -a <json file produced by previous step>

Generating artificial load::

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
