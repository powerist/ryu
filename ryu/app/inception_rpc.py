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


class InceptionRpc(object):
    """Inception Cloud rpc module for handling rpc calls"""

    def __init__(self, inception):
        self.inception = inception

        # name shortcuts
        self.zk = inception.zk
        self.mac_to_position = self.inception.mac_to_position
        self.dpid_to_conns = self.inception.dpid_to_conns
        self.inception_arp = inception.inception_arp

    def setup_inter_dcenter_flows(self, local_mac, remote_mac):
        """Set up flows towards gateway switch"""
        txn = self.zk.transaction()
        self.inception.setup_inter_dcenter_flows(local_mac, remote_mac, txn)
        txn.commit()

    def update_arp_mapping(self, ip, mac, dcenter):
        """Update remote ip_mac mapping"""
        txn = self.zk.transaction()
        self.inception_arp.update_arp_mapping(ip, mac, dcenter, txn)
        txn.commit()

    def send_arp_reply(self, src_ip, src_mac, dst_ip, dst_mac):
        self.inception_arp.send_arp_reply(src_ip, src_mac, dst_ip, dst_mac)

    def broadcast_arp_request(self, src_ip, src_mac, dst_ip, dpid):
        self.inception_arp.broadcast_arp_request(src_ip, src_mac, dst_ip, dpid)

    def update_position(self, mac, dcenter, dpid, port, vmac):
        txn = self.zk.transaction()
        self.inception.update_position(mac, dcenter, dpid, port, vmac, txn)
        txn.commit()

    def redirect_flow(self, dpid_old, vmac_old, vmac_new, dcenter_new):
        """
        Update a local flow towards a used-to-own mac,
        mac has been migrated to the datacenter who calls the rpc
        """
        txn = self.zk.transaction()
        if dcenter_new == self.inception.dcenter:
            return

        gateway_dpid = self.inception.gateway
        gateway_ip = self.inception.dpid_to_ip[gateway_dpid]
        fwd_port = self.inception.dpid_to_conns[dpid_old][gateway_ip]

        self.inception.set_local_flow(dpid_old, vmac_old, vmac_new, fwd_port,
                                      txn, False)
        txn.commit()
