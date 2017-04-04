#!/bin/bash

# Code to test the suitability of Python

rates=( 1 2 3 4 5 6 7 8 9 10 )

for rate in "${rates[@]}"
do
    echo "Sending rate: ${rate}"
    python3 metameasurement.py -Mrtt:interface=en0:type=hoplimited:maxttl=1:dest=atlas.cs.wisc.edu:rate=${rate} -f r${rate}
done
