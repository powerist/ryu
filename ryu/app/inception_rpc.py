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

import logging
import os

from ryu.app import inception_util as i_util
from ryu.app import inception_conf as i_conf

LOGGER = logging.getLogger(__name__)


class InceptionRpc(object):
    """Inception Cloud rpc module for handling rpc calls"""

    def __init__(self, inception):
        self.inception = inception
        self.i_arp = inception.inception_arp

    def rpc_setup_inter_dcenter_flows(self, local_mac, remote_mac, txn=None):
        """Set up flows towards gateway switch"""
        self.inception.setup_inter_dcenter_flows(local_mac,
                                                 remote_mac,
                                                 txn=None)

    def rpc_arp_learning(self, ip, mac, dcenter_id):
        """Update ip_mac mapping"""
        mac_dcenter = i_util.tuple_to_str((mac, dcenter_id))
        self.inception.ip_to_mac_dcenter[ip] = (mac, dcenter_id)
        self.inception.zk.create(
            os.path.join(i_conf.IP_TO_MAC_DCENTER, ip), mac_dcenter)
        LOGGER.info("Update remote ip_mac: (ip=%s) => (mac=%s, dcenter=%s)",
                    ip, mac, dcenter_id)

    def rpc_send_arp_reply(self, src_ip, src_mac, dst_ip, dst_mac, txn=None):
        self.i_arp.send_arp_reply(src_ip, src_mac, dst_ip, dst_mac, txn)

    def rpc_broadcast_arp_request(self, src_ip, src_mac, dst_ip, dpid):
        self.i_arp.broadcast_arp_request(src_ip, src_mac, dst_ip, dpid)
