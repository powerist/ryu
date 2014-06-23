#!/bin/bash

SSHS='ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'

function get_vm_name {
    for i in `cat compute_ip.txt`; do
        $SSHS $i 'sudo docker.io inspect `sudo docker.io  ps -q`' |grep Name |cut -f 2 -d '/' |cut -f 1 -d '"'
    done
}

function get_vm_ip {
    for i in `get_vm_name`; do
        echo "10.2.$i"
    done
}
