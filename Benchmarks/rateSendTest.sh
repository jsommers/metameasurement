#!/bin/bash

# Code to test the suitability of Python

for ttl in {1..3}
do 
    for rate in {1..100}
    do
        echo "Sending rate: ${rate}, TTL: ${ttl}"
        python3 metameasurement.py -Mcpu -Mrtt:interface=en0:type=hoplimited:maxttl=${ttl}:dest=atlas.cs.wisc.edu:rate=${rate} -f r${rate}_ttl${ttl}
    done
done
