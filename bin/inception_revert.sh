#!/bin/bash

# Usage: ./inception_revert.sh

bridge_name=obr2

# Deconnect from the controller
sudo ovs-vsctl del-controller $bridge_name

# Delete fail-mode. When connection to the controller is lost,
# The virtual switch will act like a traditional switch
sudo ovs-vsctl del-fail-mode $bridge_name

# Clear Openflow protocols
sudo ovs-vsctl clear Bridge $bridge_name protocols

# Enable STP
sudo ovs-vsctl set Bridge $bridge_name stp_enable=true
 
# Delete all Openflow flows
sudo ovs-ofctl del-flows $bridge_name

# Add a flow for normal operation
sudo ovs-ofctl add-flow $bridge_name "table=0, actions=NORMAL"
