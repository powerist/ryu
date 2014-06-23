#!/bin/bash

SSHS='ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'

for i in `cat vm_ip.txt`; do 
    echo $i 
    $SSHS $i 'rm ping.log; rm /tmp/do_test.pid';     
done
