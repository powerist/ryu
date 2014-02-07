# -*- coding: utf-8 -*-

# vim: tabstop=4 shiftwidth=4 softtabstop=4

#    Copyright (C) 2014 AT&T Labs All Rights Reserved.
#    Copyright (C) 2014 University of Pennsylvania All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""A global view of Inception configurations, to ease management"""

import os

from oslo.config import cfg

CONF = cfg.CONF

CONF.register_opts([
    cfg.StrOpt('zk_servers',
               default='127.0.0.1:2181',
               help="Addresses of ZooKeeper servers, ',' as sep"),
    cfg.StrOpt('zk_election',
               default='/election',
               help='Path of leader election in ZooKeeper'),
    cfg.StrOpt('zk_data',
               default='/data',
               help="Path for storing all network data"),
    cfg.StrOpt('zk_failover',
               default='/failover',
               help="Path for storing failover logging"),
    cfg.StrOpt('zk_log_level',
               default='warning',
               help="Log level for Kazoo/ZooKeeper"),
    cfg.StrOpt('ip_prefix',
               default='192.168',
               help="X1.X2 in your network's IP address X1.X2.X3.X4"),
])

# Path in ZooKeeper, under which records the "IP address" of a VM
# where a switch ("dpid") resides.
#
# {dpid => IP address}
DPID_TO_IP = os.path.join(CONF.zk_data, 'dpid_to_ip')

# Path in ZooKeeper, under which records the neighboring relations
# of each switch.
# "IP address": address of remote VMs.
# "port": port number of dpid connecting IP address.
#
# {dpid => {IP address => port}}
DPID_TO_CONNS = os.path.join(CONF.zk_data, 'dpid_to_conns')

# Path in ZooKeeper, under which records the switch ("dpid") to
# which a local "mac" connects, as well as the "port" of the
# connection.
#
# {MAC => (dpid, port)}
MAC_TO_DPID_PORT = os.path.join(CONF.zk_data, 'mac_to_dpid_port')

# Path in ZooKeeper, under which record "dpid"s that has installed
# a rule forwarding packets to "mac".
#
# {mac => {dpid => (True)}}
MAC_TO_FLOWS = os.path.join(CONF.zk_data, 'mac_to_flows')

# Path in ZooKeeper, under which records mapping from IP address
# to MAC address of end hosts for address resolution
#
# {IP address => MAC address}
IP_TO_MAC = os.path.join(CONF.zk_data, 'ip_to_mac')

# Path in ZooKeeper, under which records the switch to which DHCP
# server connects
#
DHCP_SWITCH_DPID = os.path.join(CONF.zk_data, 'dhcp_switch_dpid')

# Path in ZooKeeper, under which records the port of switch on
# which DHCP server connects
#
DHCP_SWITCH_PORT = os.path.join(CONF.zk_data, 'dhcp_switch_port')
