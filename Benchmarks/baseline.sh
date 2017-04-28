#!/bin/bash 

INTF=eth0
DEST=10.42.42.3
DURATION=3600
NCPU=`cat /proc/cpuinfo | grep '^processor' | wc -l`
CPUPIN=$(($NCPU-1))
CPUAFF="-C${CPUPIN}"
SLEEP=10

for MON in cpu mem io netstat cpu:interval=5 rtt:interface=${INTF}:type=ping:dest=${DEST} rtt:interface=${INTF}:type=hoplimited:maxttl=1:dest=8.8.8.8 ; do
    MONNAME=`echo $MON | perl -pe 's/[:\.]/_/g' | perl -pe 's/=//g'`
    OUTNAME=baseline_${DURATION}_${MONNAME}
    echo ${OUTNAME}
    date
    python3 metameasurement.py $CPUAFF -M${MON} -c "sleep $DURATION" -F ${OUTNAME} -l
    sleep ${SLEEP}
done

OUTNAME=baseline_${DURATION}_allping
echo ${OUTNAME}
date
python3 metameasurement.py $CPUAFF -Mcpu -Mmem -Mio -Mnetstat -Mrtt:interface=$INTF:type=ping:dest=$DEST -c "sleep $DURATION" -F ${OUTNAME} -l

echo "done"
