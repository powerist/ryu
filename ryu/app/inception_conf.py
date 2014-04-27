# -*- coding: utf-8 -*-

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

from ryu.ofproto import ofproto_v1_2

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
    cfg.StrOpt('dcenter',
               default='0',
               help="Datacenter identification"),
    cfg.IntOpt('rpc_port',
               default=8000,
               help="The port for XMLRPC call"),
    cfg.ListOpt('ofp_versions',
                default=[ofproto_v1_2.OFP_VERSION],
                help="Default OpenFlow versions to use"),
    # TODO: multiple neighbor datacenters
    cfg.StrOpt('peer_dcenters',
               default='0',
               help="Neighbor datacenter identification"),
    # TODO: multiple remote controllers
    cfg.StrOpt('remote_controller',
               default='127.0.0.1',
               help="IP address of remote controller"),
    # TODO: remove hardcoding
    cfg.IntOpt('num_switches',
               default=4,
               help=("The number of switches in total for each datacenter,"
                     " for failure recovery")),
])

"""
Path in ZooKeeper, under which records a datacenter ("dcenter") in
which a guest VM ("MAC") resides, the switch ("DPID") the VM is connected
to, the "port" of the connection, and its virtual mac.

{MAC => (dcenter, dpid, port, vmac)}
"""
MAC_TO_POSITION = os.path.join(CONF.zk_data, 'mac_to_position')

"""
Path in ZooKeeper, under which records mapping from VM's "IP" address to
VM's "MAC" address for address resolution protocol (ARP).

{IP => MAC}
"""
IP_TO_MAC = os.path.join(CONF.zk_data, 'ip_to_mac')

"""
Path in ZooKeeper, under which records mapping from switch ("DPID") to
its virtual "MAC" address.

{dpid => vmac}
"""
DPID_TO_VMAC = os.path.join(CONF.zk_data, 'dpid_to_vmac')

DCENTER_MASK = "ff:ff:00:00:00:00"
SWITCH_MASK = "ff:ff:ff:ff:00:00"
SWITCH_MAXID = 65535
VM_MASK = "ff:ff:ff:ff:ff:00"
VM_MAXID = 65535

# Failover type
MIGRATION = "migration"
SOURCE_LEARNING = "source_learning"
ARP_LEARNING = "arp_learning"
RPC_REDIRECT_FLOW = "rpc_redirect_flow"
RPC_GATEWAY_FLOW = "rpc_gateway_flow"
