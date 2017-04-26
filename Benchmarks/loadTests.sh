#!/usr/bin/env bash 

# NB: assumes that the runLoad script has been properly, e.g., runtime
# number of cores, other parameters.

# NB: assumes that pyvenv is sourced correctly into current shell 
# when this is executed


#DURATION=30
#COMMAND="sleep $DURATION"
INTF="eth0"
TARGET="8.8.8.8"
SLEEP="30"
# NB: this scamper command takes approx 2.5 minutes (150 sec)
LOADNAME="load1"
MONITOR=`hostname`

#METAARGS="-Mcpu -Mmem -Mio -Mnetstat -Mrtt:interface=${INTF}:type=hoplimited:maxttl=3:dest=${TARGET}"
METAARGS="-Mcpu -Mmem -Mio -Mnetstat -Mrtt:interface=${INTF}:type=ping:dest=10.42.42.3 -Mrtt:interface=${INTF}:type=ping:dest=192.168.100.254 -Mrtt:interface=${INTF}:type=ping:dest=149.43.80.1"

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
    python3 metameasurement.py ${METAARGS} -F ${LOADNAME}_${LTYPE} -l -c "scamper -O warts -o ${WARTSOUT} -c \"ping -P icmp-echo -c 180 -s64\" -i 8.8.8.8 -M ${MONITOR}"

    killall python3
    sleep $SLEEP
done

exit

## obsolete stuff below; to be deleted...

WARTSOUT=${LOADNAME}_noload.warts
python3 metameasurement.py -Mcpu -Mmem -Mio -Mnetstat -Mrtt:interface=$INTF:type=hoplimited:maxttl=3:dest=$TARGET -c "scamper -c \"ping -P icmp-echo -c 200 -s 64\" -f Benchmarks/targets.txt -M $MONITOR -O warts -o $WARTSOUT" -F ${LOADNAME}_noload -l 


# expt with artificial cpu load
WARTSOUT=${LOADNAME}_cpuload.warts
cd LoadGenerator 
./runLoad.sh c > ${LOADNAME}_cpuload.txt &
cd ..
#python3 metameasurement.py -Mcpu -Mmem -Mio -Mnetstat -Mrtt:interface=$INTF:type=ping:dest=$TARGET -c "$COMMAND" -F $LOADNAME_cpuload -l
python3 metameasurement.py -Mcpu -Mmem -Mio -Mnetstat -Mrtt:interface=$INTF:type=hoplimited:maxttl=3:dest=$TARGET -c "scamper -c \"ping -P icmp-echo -c 200 -s 64\" -f Benchmarks/targets.txt -M $MONITOR -O warts -o $WARTSOUT" -F ${LOADNAME}_cpuload -l 
killall python3
sleep $SLEEP

# expt with artificial mem load
WARTSOUT=${LOADNAME}_memload.warts
cd LoadGenerator 
./runLoad.sh m > ${LOADNAME}_memload.txt &
cd ..
#python3 metameasurement.py -Mcpu -Mmem -Mio -Mnetstat -Mrtt:interface=$INTF:type=ping:dest=$TARGET -c "$COMMAND" -F ${LOADNAME}_memload -l 
python3 metameasurement.py -Mcpu -Mmem -Mio -Mnetstat -Mrtt:interface=$INTF:type=hoplimited:maxttl=3:dest=$TARGET -c "scamper -c \"ping -P icmp-echo -c 200 -s 64\" -f Benchmarks/targets.txt -M $MONITOR -O warts -o $WARTSOUT" -F ${LOADNAME}_memload -l 
killall python3
sleep $SLEEP

# expt with artificial disk/io load
WARTSOUT=${LOADNAME}_ioload.warts
cd LoadGenerator 
./runLoad.sh d > ${LOADNAME}_ioload.txt &
cd ..
# python3 metameasurement.py -Mcpu -Mmem -Mio -Mnetstat -Mrtt:interface=$INTF:type=ping:dest=$TARGET -c "$COMMAND" -F ${LOADNAME}_ioload -l 
python3 metameasurement.py -Mcpu -Mmem -Mio -Mnetstat -Mrtt:interface=$INTF:type=hoplimited:maxttl=3:dest=$TARGET -c "scamper -c \"ping -P icmp-echo -c 200 -s 64\" -f Benchmarks/targets.txt -M $MONITOR -O warts -o $WARTSOUT" -F ${LOADNAME}_ioload -l 
killall python3
sleep $SLEEP

# expt with artificial net load
WARTSOUT=${LOADNAME}_netload.warts
cd LoadGenerator 
./runLoad.sh n > ${LOADNAME}_netload.txt &
cd ..
# python3 metameasurement.py -Mcpu -Mmem -Mio -Mnetstat -Mrtt:interface=$INTF:type=ping:dest=$TARGET -c "$COMMAND" -F ${LOADNAME}_netload -l 
python3 metameasurement.py -Mcpu -Mmem -Mio -Mnetstat -Mrtt:interface=$INTF:type=hoplimited:maxttl=3:dest=$TARGET -c "scamper -c \"ping -P icmp-echo -c 200 -s 64\" -f Benchmarks/targets.txt -M $MONITOR -O warts -o $WARTSOUT" -F ${LOADNAME}_netload -l 
killall python3

