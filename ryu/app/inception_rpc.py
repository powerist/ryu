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
import logging

from oslo.config import cfg

from ryu.app import inception_util as i_util

LOGGER = logging.getLogger(__name__)

CONF = cfg.CONF
CONF.import_opt('zookeeper_storage', 'ryu.app.inception_conf')
CONF.import_opt('arp_timeout', 'ryu.app.inception_conf')


class InceptionRpc(object):
    """Inception Cloud rpc module for handling rpc calls"""
    def __init__(self, inception):
        self.inception = inception
        self.dcenter_id = inception.dcenter_id

        # name shortcuts
        self.arp_manager = inception.arp_manager
        self.topology = inception.topology
        self.flow_manager = inception.flow_manager
        self.vmac_manager = inception.vmac_manager
        self.tenant_manager = inception.tenant_manager
        self.vm_manager = inception.vm_manager
        self.switch_manager = inception.switch_manager
        self.zk_manager = inception.zk_manager

    def do_rpc(self, func_name, rpc_id, arguments):
        LOGGER.info("RPC: %s", func_name)
        znode = i_util.tuple_to_str((func_name, rpc_id))
        self.zk_manager.add_rpc_log(znode, arguments)
        txn = self.zk_manager.create_transaction()
        func = getattr(self, func_name)
        func(txn, *arguments)
        self.zk_manager.del_rpc_log(znode, txn)

    def update_arp_mapping(self, txn, ip, mac):
        """Update remote ip_mac mapping"""
        self.arp_manager.update_mapping(ip, mac)
        self.zk_manager.log_arp_mapping(ip, mac, txn)

    def update_swc_id(self, txn, dcenter, dpid, switch_id):
        self.inception.switch_manager.update_swc_id(dcenter, dpid, switch_id)
        self.zk_manager.log_dpid_id(dcenter, dpid, switch_id, txn)
        # Locally reconstruct switch vmac
        self.vmac_manager.create_swc_vmac(dcenter, dpid, switch_id)

    def update_vm(self, txn, dcenter, dpid, port, mac, vm_id):
        self.vm_manager.update_vm(dcenter, dpid, port, mac, vm_id)
        self.vmac_manager.create_vm_vmac(mac, self.tenant_manager,
                                         self.vm_manager)
        self.zk_manager.log_vm(dcenter, dpid, port, mac, vm_id, txn)

    def del_tenant_filter(self, txn, dpid, mac):
        self.inception.flow_manager.del_tenant_filter(dpid, mac)

    def handle_dc_migration(self, txn, mac, dcenter_old, dpid_old, port_old,
                            vm_id_old, dcenter_new, dpid_new, port_new,
                            vm_id_new):
        # Handle migration happening in another datacenter
        self.vm_manager.update_vm(dcenter_new, dpid_new, port_new, mac,
                                  vm_id_new)
        tenant_id = self.tenant_manager.get_tenant_id(mac)
        vmac_old = self.vmac_manager.construct_vmac(dcenter_old, dpid_old,
                                                  vm_id_old, tenant_id)
        vmac_new = self.vmac_manager.construct_vmac(dcenter_new, dpid_new,
                                                  vm_id_new, tenant_id)
        # Handle live migration happening in dcenter_new
        if dcenter_old == self.dcenter_id:
            # The vm used to belong to this datacenter
            self.switch_manager.recollect_vm_id(vm_id_old, dpid_old)
            dpid_gws = self.topology.get_gateways()
            for dpid_gw in dpid_gws:
                fwd_port = self.topology.get_fwd_port(dpid_old, dpid_gw)
                self.flow_manager.set_local_flow(dpid_old, vmac_old, vmac_new,
                                                 fwd_port, False)
        else:
            # The vm was never in this datacenter
            dpid_gws = self.topology.get_gateways()
            for dpid_gw in dpid_gws:
                fwd_port = self.topology.get_dcenter_port(dpid_gw, dcenter_new)
                self.flow_manager.set_local_flow(dpid_gw, vmac_old, vmac_new,
                                                 fwd_port)

        self.inception.notify_vmac_update(mac, vmac_old, vmac_new)
        self.zk_manager.move_vm(mac, dcenter_old, dpid_old, port_old,
                                dcenter_new, dpid_new, port_new, vm_id_new,
                                txn)
