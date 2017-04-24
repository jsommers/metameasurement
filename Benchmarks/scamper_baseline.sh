#!/bin/bash -x
HOST=`hostname
DT=`date +"%F-%T"`
scamper -c "ping -P icmp-echo -c 30 -s 64" -p 10 -w 5 -f Benchmarks/targets.txt -M ${HOST} -O warts -o ${HOST}_${DT}_baseline.warts
