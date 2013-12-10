#!/bin/bash

# Usage: ./inception_apply.sh <controller_ip>

controller_ip=$1
bridge_name=obr1
echo 'controller_ip: '$controller_ip

# Connect the OVS to the controller
ovs-vsctl set-controller $bridge_name tcp:$controller_ip:6633

# Configure the controller to be out of band.  With controller "in
# band", Open vSwitch sets up special "hidden" flows to make sure that
# traffic can make it back and forth between OVS and the controller.
# These hidden flows are removed when controller is set "out of band"
ovs-vsctl set controller $bridge_name connection-mode=out-of-band

# Set fail-mode to secure so that when the connection to the
# controller is lost, OVS will not perform normal (traditional) L2/L3
# functionality
ovs-vsctl set bridge $bridge_name fail-mode=secure

# Specify OpenFlow version
ovs-vsctl set bridge $bridge_name protocols=OpenFlow10,OpenFlow12,OpenFlow13

# Disable STP
ovs-vsctl set Bridge $bridge_name stp_enable=false
