#!/bin/bash

for i in `cat vm_ip.txt`; do
    ping -c1 ${i}>/dev/null
    if [ $? -ne 0 ]; then
        echo "${i} is not alive";
    else
        echo  "${i} is alive";
    fi
done
