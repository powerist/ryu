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

from ryu.lib.dpid import str_to_dpid
from ryu.lib.packet import dhcp

LOGGER = logging.getLogger(__name__)

CONF = cfg.CONF
CONF.import_opt('zookeeper_storage', 'ryu.app.inception_conf')

SERVER_PORT = 67
CLIENT_PORT = 68


class InceptionDhcp(object):
    """Inception Cloud DHCP module for handling DHCP packets."""

    def __init__(self, inception):
        self.switch_dpid = None
        self.switch_port = None

        # name shortcuts
        self.dpset = inception.dpset
        self.dcenter_id = inception.dcenter_id
        self.arp_manager = inception.arp_manager
        self.vm_manager = inception.vm_manager
        self.zk_manager = inception.zk_manager
        self.rpc_manager = inception.rpc_manager

    def update_server(self, dpid, port):
        if self.switch_dpid is not None and self.switch_port is not None:
            LOGGER.warning("DHCP-server-connected switch registered before!")

        self.switch_dpid = dpid
        self.switch_port = port
        LOGGER.info("DHCP server: (dpid=%s), (port=%s)", dpid, port)

    def handle(self, dhcp_header, raw_data):
        # Process DHCP packet
        LOGGER.info("Handle DHCP packet")

        if self.switch_dpid is None or self.switch_port is None:
            LOGGER.warning("No DHCP server has been found!")
            return

        # Do ARP learning on a DHCP ACK message
        for option in dhcp_header.options.option_list:
            if option.tag == dhcp.DHCP_MESSAGE_TYPE_OPT:
                option_value = ord(option.value)
                if option_value == dhcp.DHCP_ACK:
                    ip_addr = dhcp_header.yiaddr
                    mac_addr = dhcp_header.chaddr
                    if not self.arp_manager.mapping_exist(ip_addr):
                        self.arp_manager.learn_arp_mapping(ip_addr, mac_addr,
                                                           self.rpc_manager)
                        self.rpc_manager.rpc_update_arp(ip_addr, mac_addr)
                        self.zk_manager.log_arp_mapping(ip_addr, mac_addr)
                break

        # A packet received from client. Find out the switch connected
        # to dhcp server and forward the packet
        if dhcp_header.op == dhcp.DHCP_BOOT_REQUEST:
            LOGGER.info("Forward DHCP message to server at (switch=%s) "
                        "(port=%s)", self.switch_dpid, self.switch_port)
            datapath = self.dpset.get(str_to_dpid(self.switch_dpid))
            action_out = [
                datapath.ofproto_parser.OFPActionOutput(
                    int(self.switch_port))]
            datapath.send_msg(
                datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=0xffffffff,
                    in_port=datapath.ofproto.OFPP_LOCAL,
                    data=raw_data,
                    actions=action_out))

        # A packet received from server. Find out the mac address of
        # the client and forward the packet to it.
        elif dhcp_header.op == dhcp.DHCP_BOOT_REPLY:
            _, dpid, port = self.vm_manager.get_position(dhcp_header.chaddr)
            LOGGER.info("Forward DHCP message to client (mac=%s) at "
                        "(switch=%s, port=%s)",
                        dhcp_header.chaddr, dpid, port)
            datapath = self.dpset.get(str_to_dpid(dpid))
            action_out = [datapath.ofproto_parser.OFPActionOutput(int(port))]
            datapath.send_msg(
                datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=0xffffffff,
                    in_port=datapath.ofproto.OFPP_LOCAL,
                    data=raw_data,
                    actions=action_out))
