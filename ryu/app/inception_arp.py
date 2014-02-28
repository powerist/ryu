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
from ryu.lib.dpid import dpid_to_str
from ryu.lib.dpid import str_to_dpid
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet
from ryu.ofproto import ether

LOGGER = logging.getLogger(__name__)


class InceptionArp(object):
    """Inception Cloud ARP module for handling ARP packets."""

    def __init__(self, inception):
        self.inception = inception

    def handle(self, dpid, in_port, arp_header, txn):
        LOGGER.info("Handle ARP packet")

        # Do {ip => mac} learning
        self._do_arp_learning(arp_header, txn)
        # Process arp request
        if arp_header.opcode == arp.ARP_REQUEST:
            self._handle_arp_request(dpid, in_port, arp_header, txn)
        # Process arp reply
        elif arp_header.opcode == arp.ARP_REPLY:
            self._handle_arp_reply(dpid, arp_header, txn)

    def _do_arp_learning(self, arp_header, txn):
        """Learn IP => MAC mapping from a received ARP packet, update
        ip_to_mac table.
        """
        src_ip = arp_header.src_ip
        src_mac = arp_header.src_mac

        if src_ip not in self.inception.zk.get_children(i_conf.IP_TO_MAC):
            txn.create(os.path.join(i_conf.IP_TO_MAC, src_ip), src_mac)
            LOGGER.info("Learn: (ip=%s) => (mac=%s)", src_ip, src_mac)

    def _handle_arp_request(self, dpid, in_port, arp_header, txn):
        """Process ARP request packet."""
        src_ip = arp_header.src_ip
        src_mac = arp_header.src_mac
        dst_ip = arp_header.dst_ip

        datapath = self.inception.dpset.get(str_to_dpid(dpid))
        ofproto_parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        LOGGER.info("ARP request: (ip=%s) query (ip=%s)", src_ip, dst_ip)
        # If entry not found, do nothing.
        if dst_ip not in self.inception.zk.get_children(i_conf.IP_TO_MAC):
            LOGGER.info("Entry for (ip=%s) not found.", dst_ip)
        # Entry exists
        else:
            # Setup data forwarding flows
            result_dst_mac, _ = self.inception.zk.get(
                os.path.join(i_conf.IP_TO_MAC, dst_ip))
            self.inception.setup_switch_fwd_flows(src_mac, dpid,
                                                  result_dst_mac, txn)
            # Construct ARP reply packet and send it to the host
            LOGGER.info("Hit: (dst_ip=%s) <=> (dst_mac=%s)",
                        dst_ip, result_dst_mac)

            arp_reply = arp.arp(opcode=arp.ARP_REPLY,
                                dst_mac=src_mac,
                                src_mac=result_dst_mac,
                                dst_ip=src_ip,
                                src_ip=dst_ip)
            eth_reply = ethernet.ethernet(ethertype=ether.ETH_TYPE_ARP,
                                          src=arp_reply.src_mac,
                                          dst=arp_reply.dst_mac)
            packet_reply = packet.Packet()
            packet_reply.add_protocol(eth_reply)
            packet_reply.add_protocol(arp_reply)
            packet_reply.serialize()
            actions_out = [ofproto_parser.OFPActionOutput(int(in_port))]
            datapath.send_msg(
                ofproto_parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=0xffffffff,
                    in_port=ofproto.OFPP_LOCAL,
                    data=packet_reply.data,
                    actions=actions_out))
            LOGGER.info("Answer ARP reply to (host=%s) (mac=%s) on (port=%s) "
                        "on behalf of (ip=%s) (mac=%s)",
                        arp_reply.dst_ip, arp_reply.dst_mac, in_port,
                        arp_reply.src_ip, arp_reply.src_mac)

    def _handle_arp_reply(self, dpid, arp_header, txn):
        """Process ARP reply packet."""
        src_ip = arp_header.src_ip
        src_mac = arp_header.src_mac
        dst_ip = arp_header.dst_ip
        dst_mac = arp_header.dst_mac

        LOGGER.info("ARP reply: (ip=%s) answer (ip=%s)", src_ip, dst_ip)
        zk_path = os.path.join(i_conf.MAC_TO_DPID_PORT, dst_mac)
        if self.inception.zk.exists(zk_path):
            # If I know to whom to forward back this ARP reply
            dst_dpid_port, _ = self.inception.zk.get(zk_path)
            dst_dpid, dst_port = i_util.str_to_tuple(dst_dpid_port)
            # Setup data forwarding flows
            self.inception.setup_switch_fwd_flows(src_mac, dpid, dst_mac, txn)
            # Forward ARP reply
            arp_reply = arp.arp(opcode=arp.ARP_REPLY,
                                dst_mac=dst_mac,
                                src_mac=src_mac,
                                dst_ip=dst_ip,
                                src_ip=src_ip)
            eth_reply = ethernet.ethernet(ethertype=ether.ETH_TYPE_ARP,
                                          src=src_mac,
                                          dst=dst_mac)
            packet_reply = packet.Packet()
            packet_reply.add_protocol(eth_reply)
            packet_reply.add_protocol(arp_reply)
            packet_reply.serialize()

            dst_datapath = self.inception.dpset.get(str_to_dpid(dst_dpid))
            dst_ofproto_parser = dst_datapath.ofproto_parser
            dst_ofproto = dst_datapath.ofproto
            actions_out = [dst_ofproto_parser.OFPActionOutput(int(dst_port))]
            dst_datapath.send_msg(
                dst_ofproto_parser.OFPPacketOut(
                    datapath=dst_datapath,
                    buffer_id=0xffffffff,
                    in_port=dst_ofproto.OFPP_LOCAL,
                    data=packet_reply.data,
                    actions=actions_out))
            LOGGER.info("Forward ARP reply from (ip=%s) to (ip=%s) in buffer",
                        src_ip, dst_ip)
