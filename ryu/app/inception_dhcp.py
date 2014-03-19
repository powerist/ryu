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

from ryu.app import inception_conf as i_conf
from ryu.app import inception_util as i_util
from ryu.lib.dpid import str_to_dpid

LOGGER = logging.getLogger(__name__)

DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68


class InceptionDhcp(object):
    """Inception Cloud DHCP module for handling DHCP packets."""

    def __init__(self, inception):
        self.inception = inception

    def update_server(self, dpid, port):
        dhcp_switch_dpid, _ = self.inception.zk.get(i_conf.DHCP_SWITCH_DPID)
        dhcp_switch_port, _ = self.inception.zk.get(i_conf.DHCP_SWITCH_PORT)
        if dhcp_switch_port and dhcp_switch_dpid:
            LOGGER.warning("DHCP-server-connected switch registered before!")
        self.inception.zk.set(i_conf.DHCP_SWITCH_DPID, dpid)
        self.inception.zk.set(i_conf.DHCP_SWITCH_PORT, port)

    def get_server_info(self):
        # Get tuple (dpid_of_dhcpserver, port_of_dhcpserver)
        dhcp_switch_dpid, _ = self.inception.zk.get(i_conf.DHCP_SWITCH_DPID)
        dhcp_switch_port, _ = self.inception.zk.get(i_conf.DHCP_SWITCH_PORT)
        return (dhcp_switch_dpid, dhcp_switch_port)

    def handle(self, udp_header, ethernet_header, raw_data, txn):
        # Process DHCP packet
        LOGGER.info("Handle DHCP packet")

        dhcp_switch_dpid, dhcp_switch_port = self.get_server_info()

        if not dhcp_switch_dpid or not dhcp_switch_port:
            LOGGER.warning("No DHCP server has been found!")
            return

        # A packet received from client. Find out the switch connected
        # to dhcp server and forward the packet
        if udp_header.src_port == DHCP_CLIENT_PORT:
            LOGGER.info("Forward DHCP message to server at (switch=%s) "
                        "(port=%s)", dhcp_switch_dpid, dhcp_switch_port)
            datapath = self.inception.dpset.get(str_to_dpid(dhcp_switch_dpid))
            action_out = [
                datapath.ofproto_parser.OFPActionOutput(
                    int(dhcp_switch_port))]
            datapath.send_msg(
                datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=0xffffffff,
                    in_port=datapath.ofproto.OFPP_LOCAL,
                    data=raw_data,
                    actions=action_out))
        # A packet received from server. Find out the mac address of
        # the client and forward the packet to it.
        elif udp_header.src_port == DHCP_SERVER_PORT:
            dpid_port, _ = self.inception.zk.get(os.path.join(
                i_conf.MAC_TO_DPID_PORT, ethernet_header.dst))
            dpid, port = i_util.str_to_tuple(dpid_port)
            LOGGER.info("Forward DHCP message to client (mac=%s) at "
                        "(switch=%s, port=%s)",
                        ethernet_header.dst, dpid, port)
            datapath = self.inception.dpset.get(str_to_dpid(dpid))
            action_out = [datapath.ofproto_parser.OFPActionOutput(int(port))]
            datapath.send_msg(
                datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=0xffffffff,
                    in_port=datapath.ofproto.OFPP_LOCAL,
                    data=raw_data,
                    actions=action_out))
