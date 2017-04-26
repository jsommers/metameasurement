#!/bin/bash -x
HOST=`hostname`
DT=`date +"%Y%m%d%H%M%S"`
scamper -c "ping -P icmp-echo -c 200 -s 64" -p 10 -f Benchmarks/targets.txt -M ${HOST} -O warts -o ${HOST}_${DT}_baseline.warts
