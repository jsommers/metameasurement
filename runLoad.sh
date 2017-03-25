#!/bin/bash

make -C ./wilee
echo "Calibrating wilee..."
./wilee/wileE --calibrate
python loadmeta.py -d gamma -s 2 -e 2 -w 5
