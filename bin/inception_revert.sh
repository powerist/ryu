#!/bin/bash

# Usage: ./inception_revert.sh

bridge_name=obr1

# Deconnect from the controller
ovs-vsctl del-controller $bridge_name

# Delete fail-mode. When connection to the controller is lost,
# The virtual switch will act like a traditional switch
ovs-vsctl del-fail-mode $bridge_name

# Clear Openflow protocols
ovs-vsctl clear Bridge $bridge_name protocols

# Enable STP
ovs-vsctl set Bridge $bridge_name stp_enable=true
 
# Delete all Openflow flows
ovs-ofctl del-flows $bridge_name

# Add a flow for normal operation
ovs-ofctl add-flow $bridge_name "table=0, actions=NORMAL"
