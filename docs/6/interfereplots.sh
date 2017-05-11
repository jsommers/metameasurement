#!/bin/bash -x

for INTF in eth0 wlan0; do
    for X in quiet scp scp_1M scp_10M; do
        XNAME="load/interfere/${INTF}_${X}"
        if [ $X == "quiet" ]; then
            METANONE=""
        else
            METANONE="--metanone load/interfere/${INTF}_quiet.json"
        fi
        python3 interfere_plot.py --warts ${XNAME}.warts --meta ${XNAME}.json ${METANONE} -o ${INTF}_${X} --maxttl 3 
    done
done
