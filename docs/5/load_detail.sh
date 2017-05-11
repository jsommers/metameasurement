#!/bin/bash -x

python3 plot_load_detail.py --warts load/pihome/load_wlan0_cpu.warts --load load/pihome/load_wlan0_cpu.txt --meta load/pihome/load_wlan0_cpu.json --maxttl 3 --metanone load/pihome/load_wlan0_none.json --wartsnone load/pihome/load_wlan0_none.warts -o wlan0_cpu_detail --maxrtt 100
