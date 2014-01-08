"""
A global view of Inception configurations, to ease management.
"""

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
