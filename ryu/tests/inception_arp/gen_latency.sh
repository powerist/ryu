#!/bin/bash

if [ $# -ne "1" ]; then
    echo "usage: generate_latency <data file from collect_data.sh>"
    exit 1
fi

input_file=$1
test_name=$input_file

if [ -a $input_file ]; then 
    cat $input_file | grep -v 10.2.99.0 | awk {'print $9'} | cut -f 1,2 -d ',' > $test_name.all
    cat $input_file | grep -v 10.2.99.0 | grep -v same_host | awk '{print $9}' | cut -f 1,2 -d ','  > $test_name.inter_host
    cat $input_file | grep -v 10.2.99.0 | grep inter_dc | awk '{print $9}' | cut -f 1,2 -d ',' > $test_name.inter_dc
else 
    echo "input file not found."
    exit 1
fi
