#!/bin/bash

SCPS='scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'

for i in `cat vm_ip.txt`; do 
    for j in 'run_test.sh calc_exp vm_ip.txt util.sh'; do
	$SCPS -o StrictHostKeyChecking=no $j $i:~/
    done
done
