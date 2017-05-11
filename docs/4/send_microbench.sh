#!/bin/bash -x
python3 analy_microsend.py microbench/pib | tee pib_send_microbench.txt
python3 analy_microsend.py microbench/pi3 | tee pi3_send_microbench.txt


