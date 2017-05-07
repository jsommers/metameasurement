#!/bin/bash 

INTF=eth0
DEST=10.42.42.3
DURATION=900
NCPU=`cat /proc/cpuinfo | grep '^processor' | wc -l`
CPUPIN=$(($NCPU-1))
CPUAFF="-C${CPUPIN}"
SLEEP=5

for MON in cpu cpu:interval=5 rtt:interface=${INTF}:type=ping:dest=${DEST} rtt:interface=${INTF}:type=hoplimited:maxttl=1:dest=8.8.8.8 ; do
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
sleep ${SLEEP}

OUTNAME=baseline_${DURATION}_allping_interval5
echo ${OUTNAME}
date
python3 metameasurement.py $CPUAFF -Mcpu:interval=5 -Mmem:interval=5 -Mio:interval=5 -Mnetstat:interval=5 -Mrtt:interface=$INTF:type=ping:dest=$DEST:rate=0.2 -c "sleep $DURATION" -F ${OUTNAME} -l
sleep ${SLEEP}

OUTNAME=baseline_${DURATION}_allhoplimited
echo ${OUTNAME}
date
python3 metameasurement.py $CPUAFF -Mcpu -Mmem -Mio -Mnetstat -Mrtt:interface=$INTF:type=hoplimited:dest=8.8.8.8:maxttl=1 -c "sleep $DURATION" -F ${OUTNAME} -l
sleep ${SLEEP}

for H in 2 3 4 5; do
    OUTNAME=baseline_${DURATION}_allhoplimited_${H}hops
    echo ${OUTNAME}
    date
    python3 metameasurement.py $CPUAFF -Mcpu -Mmem -Mio -Mnetstat -Mrtt:interface=$INTF:type=hoplimited:dest=8.8.8.8:maxttl=${H} -c "sleep $DURATION" -F ${OUTNAME} -l
    sleep ${SLEEP}
done

OUTNAME=baseline_${DURATION}_allhoplimited_interval5
echo ${OUTNAME}
date
python3 metameasurement.py $CPUAFF -Mcpu:interval=5 -Mmem:interval=5 -Mio:interval=5 -Mnetstat:interval=5 -Mrtt:interface=$INTF:type=hoplimited:maxttl=1:dest=8.8.8.8:rate=0.2 -c "sleep $DURATION" -F ${OUTNAME} -l
sleep ${SLEEP}

echo "done"
