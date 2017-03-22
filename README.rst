
Try it out
----------

Requires Python 3.6.

::
    # install a python venv and required modules
    python3 -m venv xenv
    source xenv/bin/activate
    pip3 install -r requirements

    # give a test run (may require running as root)
    # by default, just runs "sleep 5" as the external "measurement" 
    # process.  it will take ~7/8 seconds to finish.
    python3 metameasurement.py

    # plot stuff
    python3 plotmeta.py -i localnet:icmpresults:icmprtt -i monitors:cpu:idle <json file produced by previous step>

    # see what metadata can be plotted
    python3 plotmeta <json file produced by previous step>

    # use a different external measurement tool
    python3 metameasurement.py -c "ping -c 100 www.google.com" 
