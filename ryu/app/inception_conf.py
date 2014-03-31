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
    cfg.StrOpt('datacenter_id',
               default='0',
               help="Datacenter identification"),
    cfg.StrOpt('neighbor_dcenter_id',
               default='0',
               help="Neighbor datacenter identification"),
    cfg.StrOpt('remote_controller',
               default='127.0.0.1',
               help="IP address of remote controllers"),
])

DPID_TO_IP = os.path.join(CONF.zk_data, 'dpid_to_ip')
# {dpid => local IP address}
# Path in ZooKeeper, under which records the "IP address" of a VM
# where a switch ("dpid") resides.

DPID_TO_CONNS = os.path.join(CONF.zk_data, 'dpid_to_conns')
# {dpid => {remote IP address => local port}}
# Path in ZooKeeper, under which records the neighboring relations
# of each switch.
# "IP address": address of remote VMs.
# "port": port number of dpid connecting IP address.
# dpid include gateway switches

GATEWAY = os.path.join(CONF.zk_data, 'gateway')
# Znode for storing gateway dpid
# TODO(chen): Multiple gateways

MAC_TO_POSITION = os.path.join(CONF.zk_data, 'mac_to_position')
# {MAC => (datacenter id, local dpid, local port)}
# Path in ZooKeeper, under which records datacenter in which "MAC" lies,
# the switch ("dpid") to which "MAC" connects, and "port" of the connection.

MAC_TO_FLOWS = os.path.join(CONF.zk_data, 'mac_to_flows')
# {MAC => {dpid => (True)}}
# Path in ZooKeeper, under which record "dpid"s that has installed
# a rule forwarding packets to "mac".

IP_TO_MAC = os.path.join(CONF.zk_data, 'ip_to_mac')
# {IP address => MAC address}
# Path in ZooKeeper, under which records mapping from IP address
# to MAC address of end hosts for address resolution

DHCP_SWITCH_DPID = os.path.join(CONF.zk_data, 'dhcp_switch_dpid')
# Path in ZooKeeper, under which records the switch to which DHCP
# server connects

DHCP_SWITCH_PORT = os.path.join(CONF.zk_data, 'dhcp_switch_port')
# Path in ZooKeeper, under which records the port of switch on
# which DHCP server connects
