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

    def update_arp_mapping(self, ip, mac):
        """Update remote ip_mac mapping"""
        self.arp_manager.update_mapping(ip, mac)
        self.zk_manager.log_arp_mapping(ip, mac)

    def send_arp_reply(self, src_ip, src_mac, dst_ip, dst_mac):
        self.inception.inception_arp.send_arp_reply(src_ip, src_mac, dst_ip,
                                                    dst_mac)

    def update_position(self, mac, dcenter, dpid, port):
        self.vm_manager.update_position(mac, dcenter, dpid, port)
        self.zk_manager.log_vm_position(dcenter, dpid, port, mac)

    def del_pos_in_zk(self, dcenter, dpid, port):
        self.zk_manager.del_vm_position(dcenter, dpid, port)

    def update_vmac(self, mac, vmac):
        self.inception.vmac_manager.update_vm_vmac(mac, vmac)

    def update_swc_id(self, dcenter, dpid, switch_id):
        self.inception.switch_manager.update_swc_id(dcenter, dpid, switch_id)
        self.zk_manager.log_dpid_id(dcenter, dpid, switch_id)
        # Locally reconstruct switch vmac
        self.vmac_manager.create_swc_vmac(dcenter, dpid, switch_id)

    def update_vm_id(self, mac, dpid, vm_id):
        self.inception.vm_manager.update_vm_id(mac, dpid, vm_id)
        dcenter, dpid, port = self.vm_manager.get_position(mac)
        self.zk_manager.log_vm_id(dcenter, dpid, port, mac, vm_id)
        # Locally reconstruct vm vmac
        self.vmac_manager.create_vm_vmac(mac, self.tenant_manager,
                                         self.vm_manager)

    def del_tenant_filter(self, dpid, mac):
        self.inception.flow_manager.del_tenant_filter(dpid, mac)

    def handle_dc_migration(self, mac, dcenter_old, dpid_old, port_old,
                            vm_id_old, dcenter_new, dpid_new, port_new,
                            vm_id_new):
        # Handle migration happening in another datacenter
        func_name = self.handle_dc_migration.__name__
        argument_tuple = (mac, dcenter_old, dpid_old, port_old, vm_id_old,
                          dcenter_new, dpid_new, port_new, dpid_new)
        self.zk_manager.add_rpc_log(func_name, argument_tuple)

        self.vm_manager.update_position(mac, dcenter_new, dpid_new, port_new)
        self.vm_manager.revoke_vm_id(mac, dpid_old)
        self.vm_manager.update_vm_id(mac, dpid_new, vm_id_new)
        tenant_id = self.tenant_manager.get_tenant_id(mac)
        vmac_old = self.vmac_manager.construct_vmac(dcenter_old, dpid_old,
                                                  vm_id_old, tenant_id)
        vmac_new = self.vmac_manager.construct_vmac(dcenter_new, dpid_new,
                                                  vm_id_new, tenant_id)
        # Handle live migration in dcenter_new
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
                                dcenter_new, dpid_new, port_new, vm_id_new)
        self.zk_manager.del_rpc_log(func_name)
