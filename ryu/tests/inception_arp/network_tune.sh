#!/bin/bash

SSHS='ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'

for i in `cat compute_ip.txt`; do
    $SSHS ubuntu@$i 'sudo ip link set br2 mtu 1388';
    printf "setting mtu on br2: %d\n" $?; 
done
