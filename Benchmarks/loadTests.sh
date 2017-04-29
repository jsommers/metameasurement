#!/usr/bin/env bash 

# NB: assumes that the runLoad script has been properly, e.g., runtime
# number of cores, other parameters.

# NB: assumes that pyvenv is sourced correctly into current shell 
# when this is executed

INTF="eth0"
HLTARGET="8.8.8.8"
SCTARGET="8.8.8.8"
SLEEP="30"
LOADNAME="load5"
MONITOR=`hostname`
NCPU=`cat /proc/cpuinfo | grep '^processor' | wc -l`
XCPU=$(($NCPU-1))
#CPUPIN="-C ${XCPU}"
CPUPIN=""
SCPROBES=250

METAARGS="-Mcpu -Mmem -Mio -Mnetstat -Mrtt:interface=${INTF}:type=hoplimited:maxttl=3:dest=${HLTARGET} -Mrtt:interface=${INTF}:type=ping:dest=${SCTARGET}"
#METAARGS="-Mcpu -Mmem -Mio -Mnetstat -Mrtt:interface=${INTF}:type=ping:dest=10.42.42.3 -Mrtt:interface=${INTF}:type=ping:dest=192.168.100.254 -Mrtt:interface=${INTF}:type=ping:dest=149.43.80.1"

for LTYPE in none cpu mem io net; do

    cd LoadGenerator
    if [ $LTYPE == "none" ]; then
        echo "No load"
    elif [ $LTYPE == "cpu" ]; then
        echo "Starting CPU loader"
        ./runLoad.sh c > ${LOADNAME}_${LTYPE}.txt &
    elif [ $LTYPE == "mem" ]; then
        echo "Starting MEM loader"
        ./runLoad.sh m > ${LOADNAME}_${LTYPE}.txt &
    elif [ $LTYPE == "io" ]; then
        echo "Starting IO loader"
        ./runLoad.sh d > ${LOADNAME}_${LTYPE}.txt &
    elif [ $LTYPE == "net" ]; then
        echo "Starting NET loader"
        ./runLoad.sh n > ${LOADNAME}_${LTYPE}.txt &
    fi
    cd ..

    WARTSOUT=${LOADNAME}_${LTYPE}.warts
    echo "Starting SoMeta"
    date
    python3 metameasurement.py ${CPUPIN} ${METAARGS} -F ${LOADNAME}_${LTYPE} -l -c "scamper -c \"ping -P icmp-echo -c ${SCPROBES} -s 64\" -M ${MONITOR}  -o ${LOADNAME}_${LTYPE}.warts -O warts -i ${SCTARGET}"

    killall python3
    sleep $SLEEP
done

