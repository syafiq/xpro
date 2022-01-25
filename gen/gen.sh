#!/bin/bash

CPUS=16
PKTS="1000"
CLONE_SKB="clone_skb 0"
PKT_SIZE="pkt_size 64"
COUNT="count 0"
DELAY="delay 0"
ETH="eno2"
RATEP="1000000"
function pgset() {
    local result
    echo $1 > $PGDEV
    result=`cat $PGDEV | fgrep "Result: OK:"`
    if [ "$result" = "" ]; then
        cat $PGDEV | fgrep Result:
    fi
}

for ((processor=0;processor<$CPUS;processor++))
do
    PGDEV=/proc/net/pktgen/kpktgend_$processor
    echo "Removing all devices"
    pgset "rem_device_all"
done

for ((processor=0;processor<$CPUS;processor++))
do
    PGDEV=/proc/net/pktgen/kpktgend_$processor
    echo "Adding $ETH"
    pgset "add_device $ETH@$processor"
    PGDEV=/proc/net/pktgen/$ETH@$processor
    echo "Configuring $PGDEV"
    pgset "$COUNT"
    pgset "flag QUEUE_MAP_CPU"
    pgset "$CLONE_SKB"
    pgset "frags 10"
    pgset "$PKT_SIZE"
    pgset "$DELAY"
    pgset "ratep $RATEP"
    pgset "burst 10000"
    pgset "dst 192.168.100.114"
    #pgset "dst_mac 52:54:00:27:51:ed"
    #pgset "dst_mac 52:54:00:1c:1a:46"
    #pgset "dst_mac 52:54:00:00:7d:78"
    #pgset "dst_mac 52:54:00:67:ca:74"
    pgset "udp_dst_min 5683"
    pgset "udp_dst_max 5683"
    pgset "flag IPDST_RND"
    pgset "flows 2048"
    pgset "flowlen 16"
done

PGDEV=/proc/net/pktgen/pgctrl

echo "Running... ctrl^C to stop"
pgset "start"
echo "Done"
