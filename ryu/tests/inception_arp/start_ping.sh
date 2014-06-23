#!/bin/bash

SSHS='ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'

for ip in `cat vm_ip.txt`; do 
    $SSHS $ip "/home/ubuntu/run_test.sh 0.2 > ping.log &";
    printf "starting ping on %s: %d\n" $ip $?
    sleep 1
done
