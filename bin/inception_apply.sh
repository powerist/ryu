#!/bin/bash

# Usage: ./inception_apply.sh <controller_ip_1> <controller_ip_2> ...

bridge_name=obr2
controller_urls=""
for controller_ip in $@
do
   controller_urls+="tcp:${controller_ip}:6633 "
done
echo 'controller_urls: ' $controller_urls

# Connect the OVS to the controller
sudo ovs-vsctl set-controller $bridge_name $controller_urls

# Configure the controller to be out of band.  With controller "in
# band", Open vSwitch sets up special "hidden" flows to make sure that
# traffic can make it back and forth between OVS and the controller.
# These hidden flows are removed when controller is set "out of band"
sudo ovs-vsctl set controller $bridge_name connection-mode=out-of-band

# Set fail-mode to secure so that when the connection to the
# controller is lost, OVS will not perform normal (traditional) L2/L3
# functionality
sudo ovs-vsctl set bridge $bridge_name fail-mode=secure

# Specify OpenFlow version
sudo ovs-vsctl set bridge $bridge_name protocols=OpenFlow10,OpenFlow12,OpenFlow13

# Disable STP
sudo ovs-vsctl set Bridge $bridge_name stp_enable=false
