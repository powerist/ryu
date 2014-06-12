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
from oslo.config import cfg

from ryu.app import inception_conf as i_conf

CONF = cfg.CONF
CONF.import_opt('zookeeper_storage', 'ryu.app.inception_conf')


class InceptionRpc(object):
    """Inception Cloud rpc module for handling rpc calls"""

    def __init__(self, inception):
        self.inception = inception

        # name shortcuts
        self.arp_mapping = inception.arp_mapping
        self.topology = inception.topology
        self.flow_manager = inception.flow_manager
        self.dpid_to_conns = self.inception.dpid_to_conns
        self.dcenter_to_info = self.inception.dcenter_to_info
        self.vmac_to_queries = self.inception.vmac_to_queries
        self.inception_arp = inception.inception_arp

    def setup_inter_dcenter_flows(self, local_mac, remote_mac):
        """Set up flows towards gateway switch"""

        self.inception.setup_inter_dcenter_flows(local_mac, remote_mac)

    def update_arp_mapping(self, ip, mac, dcenter):
        """Update remote ip_mac mapping"""

        self.inception.update_arp_mapping(ip, mac, dcenter)

    def send_arp_reply(self, src_ip, src_mac, dst_ip, dst_mac):
        self.inception_arp.send_arp_reply(src_ip, src_mac, dst_ip, dst_mac)

    def broadcast_arp_request(self, src_ip, src_mac, dst_ip, dpid):
        self.inception_arp.broadcast_arp_request(src_ip, src_mac, dst_ip, dpid)

    def update_position(self, mac, dcenter, dpid, port):
        self.inception.update_position(mac, dcenter, dpid, port)

    def update_vmac(self, mac, vmac):
        self.inception.vmac_manager.update_vm_vmac(mac, vmac)

    def del_tenant_filter(self, dpid, mac):
        self.inception.flow_manager.del_tenant_filter(dpid, mac)

    def redirect_local_flow(self, dpid_old, mac, vmac_old, vmac_new,
                            dcenter_new):
        """
        Update a local flow towards a used-to-own mac,
        mac has been migrated to the datacenter who calls the rpc
        """
        # Failover logging
        log_tuple = (dpid_old, mac, vmac_old, vmac_new, dcenter_new)
        if CONF.zookeeper_storage:
            self.inception.create_failover_log(i_conf.RPC_REDIRECT_FLOW,
                                               log_tuple)

        if dcenter_new == self.inception.dcenter_id:
            # This RPC is only used for multi-datacenter migration
            if CONF.zookeeper_storage:
                self.inception.delete_failover_log(i_conf.RPC_REDIRECT_FLOW)
            return

        # Redirect local flow
        gateway_dpid = self.topology.gateway
        fwd_port = self.topology.dpid_to_dpid[dpid_old][gateway_dpid]

        self.flow_manager.set_local_flow(dpid_old, vmac_old, vmac_new,
                                         fwd_port, False)

        if vmac_old not in self.vmac_to_queries:
            # The vmac_old key does not exist, indicating a duplicate RPC
            if CONF.zookeeper_storage:
                self.inception.delete_failover_log(i_conf.RPC_REDIRECT_FLOW)
            return

        # send gratuitous ARP to all local sending guests
        # TODO(chen): Only within ARP entry timeout
        for mac_query in self.vmac_to_queries[vmac_old]:
            ip = self.arp_mapping.get_ip(mac)
            ip_query = self.arp_mapping.get_ip(mac_query)
            self.inception_arp.send_arp_reply(ip, vmac_new, ip_query,
                                              mac_query)
        del self.vmac_to_queries[vmac_old]

        if CONF.zookeeper_storage:
            self.inception.delete_failover_log(i_conf.RPC_REDIRECT_FLOW)

    def set_gateway_flow(self, mac, vmac_old, vmac_new, dcenter_new):
        """Update gateway flow to rewrite an out-of-date vmac_old and
        forward accordingly, and update old local ARP caches"""

        # Failover logging
        log_tuple = (mac, vmac_old, vmac_new, dcenter_new)
        if CONF.zookeeper_storage:
            self.inception.create_failover_log(i_conf.RPC_GATEWAY_FLOW,
                                               log_tuple)

        if vmac_old not in self.vmac_to_queries:
            # The vmac_old key does not exist, indicating a duplicate RPC
            if CONF.zookeeper_storage:
                self.inception.delete_failover_log(i_conf.RPC_GATEWAY_FLOW)
            return

        if dcenter_new == self.inception.dcenter_id:
            # This RPC is only used for multi-datacenter migration
            if CONF.zookeeper_storage:
                self.inception.delete_failover_log(i_conf.RPC_GATEWAY_FLOW)
            return

        gateway = self.topology.gateway
        fwd_port = self.topology.gateway_to_dcenters[gateway][dcenter_new]
        self.flow_manager.set_local_flow(gateway, vmac_old, vmac_new, fwd_port)

        # Send gratuitous arp to all guests that have done ARP requests to mac
        for mac_query in self.vmac_to_queries[vmac_old]:
            ip = self.arp_mapping.get_ip(mac)
            ip_query = self.arp_mapping.get_ip(mac_query)
            self.send_arp_reply(ip, vmac_new, ip_query, mac_query)
        del self.vmac_to_queries[vmac_old]

        if CONF.zookeeper_storage:
            self.inception.delete_failover_log(i_conf.RPC_GATEWAY_FLOW)
