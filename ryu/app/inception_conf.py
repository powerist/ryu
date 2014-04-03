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
    cfg.StrOpt('neighbor_dcenter',
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
Path in ZooKeeper, under which records the local "IP" address of a
host where a switch ("DPID") resides.

{DPID => IP}
"""
DPID_TO_IP = os.path.join(CONF.zk_data, 'dpid_to_ip')

"""
Path in ZooKeeper, under which records the neighboring relations of
each switch.

"DPID": a host/switch.
"IP": IP address of a remote neighboring host.
"port": the local port which connects to the remote host.

{DPID => {IP => port}}
"""
DPID_TO_CONNS = os.path.join(CONF.zk_data, 'dpid_to_conns')

"""
Path in ZooKeeper, under which records a datacenter ("dcenter") in
which a guest VM ("MAC") resides, the switch ("DPID") the VM is connected
to, and the "port" of the connection.

{MAC => (dcenter, DPID, port)}
"""
MAC_TO_POSITION = os.path.join(CONF.zk_data, 'mac_to_position')

"""
Path in ZooKeeper, under which records each switch ("DPID") that has
installed a flow which forwards data packets to VM ("MAC").

{MAC => {DPID => (True)}}
"""
MAC_TO_FLOWS = os.path.join(CONF.zk_data, 'mac_to_flows')

"""
Path in ZooKeeper, under which records mapping from VM's "IP" address to
VM's "MAC" address for address resolution protocol (ARP).

{IP => MAC}
"""
IP_TO_MAC = os.path.join(CONF.zk_data, 'ip_to_mac')

"""
Znode in ZooKeeper for storing gateway switch DPID

TODO(chen): Multiple gateways
"""
GATEWAY = os.path.join(CONF.zk_data, 'gateway')
