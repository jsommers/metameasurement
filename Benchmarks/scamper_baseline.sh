#!/bin/bash -x
scamper -c "ping -P icmp-echo -c 30 -s 64" -p 10 -w 5 -f Benchmarks/targets.txt -M `hostname` -O warts -o `hostname`_baseline.warts
