#!/bin/bash

modprobe pktgen

function pgset() {
    local result

    echo $1 > $PGDEV

    result=`cat $PGDEV | fgrep "Result: OK:"`
    if [ "$result" = "" ]; then
         cat $PGDEV | fgrep Result:
    fi
}

# Config Start Here -----------------------------------------------------------

if [ -z $1 ]; then
    echo "Need argument (kpps)"
    exit
fi

duration=60

pps=$(($1*1000))
delay=$((1000000000/$pps))
count=$(($duration*$pps))

echo "Sending rate: $pps pps"


# thread config
# One CPU means one thread. One CPU example. We add eth1, eth2 respectivly.

PGDEV=/proc/net/pktgen/kpktgend_0
  echo "Removing all devices"
 pgset "rem_device_all"
  echo "Adding em2"
 pgset "add_device em2"


CLONE_SKB="clone_skb 0"
# NIC adds 4 bytes CRC
PKT_SIZE="pkt_size 60"

DELAY="delay $delay"
COUNT="count $count"


PGDEV=/proc/net/pktgen/em2
  echo "Configuring $PGDEV"
 pgset "$COUNT"
 pgset "$CLONE_SKB"
 pgset "$PKT_SIZE"
 pgset "$DELAY"
 pgset "dst 10.13.13.2"
 pgset "dst_mac 78:2b:cb:3b:c8:c8"

## Time to run
PGDEV=/proc/net/pktgen/pgctrl

 echo "Running... ctrl^C to stop"
 trap true INT
 pgset "start"
 echo "Done"
 cat /proc/net/pktgen/em2 
