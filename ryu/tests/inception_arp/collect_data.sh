#!/bin/bash

SSHS='ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'

function check_ip {
    a3=`echo $1 | cut -f 3 -d '.'`
    a4=`echo $1 | cut -f 4 -d '.'`

    b3=`echo $2 | cut -f 3 -d '.'`
    b4=`echo $2 | cut -f 4 -d '.'`
    
    if [ $(($a3/10)) -ne $(($b3/10)) ]; then
        echo "inter_dc"
    else 
        if [ $a3 -ne $b3 ]; then
            echo "inter_host"
        else 
            echo "same_host"
        fi
    fi
}

function tag_location {
while read line; do
    local_ip=`echo $line | cut -f 3 -d  ' '`
    peer_ip=`echo $line | cut -f 1 -d  ' '`
    r=`check_ip $local_ip, $peer_ip`
    echo "$line,$r"
done 
}

function get_single_node_data {
     $SSHS $1 "grep -v skip ping.log |grep -A 1 ARPING  |grep -v ^-- |sed -e 's/ARPING //' |sed -e 's/^.*time=\(.*\)/\1/' |paste - - -d,|grep -v 10.2.99.0 " | perl -ne 's/([0-9]+\.[0-9]+) (usec)/($2?$1\/1000:$1)." msec"/e; s/msec//; print "".$_' | tail -n +600 |head -300 | tag_location
}

if [ $# -ne "1" ]; then
    echo "usage: collect_data <output_file>"
    exit 1
fi

filename=$1
rm -f $filename
touch $filename

for ip in `cat vm_ip.txt`; do
    printf "getting data from %s: %d\n" $ip $?
    get_single_node_data $ip >> $1
done
