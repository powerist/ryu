#!/bin/bash

TESTHOME=/home/ubuntu/
cd $TESTHOME
echo $$ > /tmp/do_test.pid
vm_ip_list=(`cat vm_ip.txt`)
local_ip=`hostname -I`

while : ; do
    interval=$(./calc_exp $1 $RANDOM)
    /bin/sleep 5
    rand_id=`shuf -i 0-$((${#vm_ip_list[@]}-1)) -n 1`
    target_host=${vm_ip_list[$rand_id]}
    if [ $target_host == $local_ip ]; then
        echo "skip local ip"
        continue;
    fi
    arping -c 1 $target_host
    if [ $rand_id -lt 10 ]; then
        arping -c 1 10.2.99.0 
    fi
done
