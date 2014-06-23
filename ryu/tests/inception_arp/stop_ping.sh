#!/bin/bash

SSHS='ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'

for ip in `cat vm_ip.txt`; do 
    $SSHS $ip 'kill `cat /tmp/do_test.pid`; rm /tmp/do_test.pid'; 
    printf "stopping ping on %s: %d\n" $ip $?
done
