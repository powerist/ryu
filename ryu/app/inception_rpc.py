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
CONF.import_opt('arp_timeout', 'ryu.app.inception_conf')


class InceptionRpc(object):
    """Inception Cloud rpc module for handling rpc calls"""
    def __init__(self, inception):
        self.inception = inception

        # name shortcuts
        self.arp_manager = inception.arp_manager
        self.topology = inception.topology
        self.flow_manager = inception.flow_manager
        self.vmac_manager = inception.vmac_manager
        self.tenant_manager = inception.tenant_manager
        self.vm_manager = inception.vm_manager
        self.switch_manager = inception.switch_manager

    def update_arp_mapping(self, ip, mac):
        """Update remote ip_mac mapping"""
        self.arp_manager.update_mapping(ip, mac)

    def send_arp_reply(self, src_ip, src_mac, dst_ip, dst_mac):
        self.inception.inception_arp.send_arp_reply(src_ip, src_mac, dst_ip,
                                                    dst_mac)

    def update_position(self, mac, dcenter, dpid, port):
        self.vm_manager.update_position(mac, dcenter, dpid, port)

    def update_vmac(self, mac, vmac):
        self.inception.vmac_manager.update_vm_vmac(mac, vmac)

    def update_swc_id(self, dcenter, dpid, switch_id):
        self.inception.switch_manager.update_swc_id(dcenter, dpid, switch_id)
        # Locally reconstruct switch vmac
        self.vmac_manager.create_swc_vmac(dcenter, dpid, switch_id)

    def update_vm_id(self, mac, vm_id):
        self.inception.vm_manager.update_vm_id(mac, vm_id)
        # Locally reconstruct vm vmac
        self.vmac_manager.create_vm_vmac(mac, self.tenant_manager,
                                         self.vm_manager)

    def revoke_vm_id(self, mac, vm_id, dpid):
        self.vm_manager.revoke_vm_id(mac, vm_id)
        self.switch_manager.recollect_vm_id(vm_id, dpid)

    def del_tenant_filter(self, dpid, mac):
        self.inception.flow_manager.del_tenant_filter(dpid, mac)

    def redirect_local_flow(self, dpid_old, mac, vmac_old, vmac_new):
        """
        Update a local flow, which was towards a used-to-own mac,
        mac has been migrated to the datacenter who calls the rpc
        """
        # Failover logging
        log_tuple = (dpid_old, mac, vmac_old, vmac_new)
        if CONF.zookeeper_storage:
            self.inception.create_failover_log(i_conf.RPC_REDIRECT_FLOW,
                                               log_tuple)

        # Redirect local flow
        dpid_gw = self.topology.get_gateway()
        fwd_port = self.topology.get_fwd_port(dpid_old, dpid_gw)

        self.flow_manager.set_local_flow(dpid_old, vmac_old, vmac_new,
                                         fwd_port, False)
        # Send gratuitous ARP to all local sending guests
        # TODO(chen): Only within ARP entry timeout
        for mac_query in self.vmac_manager.get_query_macs(vmac_old):
            ip = self.arp_manager.get_ip(mac)
            ip_query = self.arp_manager.get_ip(mac_query)
            self.inception.inception_arp.send_arp_reply(ip, vmac_new, ip_query,
                                                        mac_query)
        self.vmac_manager.del_vmac_query(vmac_old)

        if CONF.zookeeper_storage:
            self.inception.delete_failover_log(i_conf.RPC_REDIRECT_FLOW)

    def set_gateway_flow(self, mac, vmac_old, vmac_new, dcenter_new):
        """Update gateway flow to rewrite an out-of-date vmac_old to vmac_new
        and forward accordingly, and update old local ARP caches"""

        # Failover logging
        log_tuple = (mac, vmac_old, vmac_new, dcenter_new)
        if CONF.zookeeper_storage:
            self.inception.create_failover_log(i_conf.RPC_GATEWAY_FLOW,
                                               log_tuple)

        dpid_gw = self.topology.get_gateway()
        fwd_port = self.topology.get_dcenter_port(dcenter_new)
        self.flow_manager.set_local_flow(dpid_gw, vmac_old, vmac_new, fwd_port)

        # Send gratuitous arp to all guests that have done ARP requests to mac
        for mac_query in self.vmac_manager.get_query_macs(vmac_old):
            ip = self.arp_manager.get_ip(mac)
            ip_query = self.arp_manager.get_ip(mac_query)
            self.send_arp_reply(ip, vmac_new, ip_query, mac_query)
        self.vmac_manager.del_vmac_query(vmac_old)

        if CONF.zookeeper_storage:
            self.inception.delete_failover_log(i_conf.RPC_GATEWAY_FLOW)
