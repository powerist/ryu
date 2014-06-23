#!/bin/bash

if [ $# -ne "2" ]; then
    echo "usage: generate_latency <data file from collect_data.sh> <output file name>"
    exit 1
fi

input_file=$1
test_name=$2

if [ -a $input_file ]; then 
    cat $input_file | awk {'print $9'} | cut -f 1 -d ',' > $test_name.all
    cat $input_file | grep -v same_host | awk '{print $9}' | cut -f 1 -d ','  > $test_name.inter_host
    cat $input_file | grep inter_dc | awk '{print $9}' | cut -f 1 -d ',' > $test_name.inter_dc
else 
    echo "input file not found."
    exit 1
fi
