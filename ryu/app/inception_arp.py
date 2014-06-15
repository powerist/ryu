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

from ryu.app import inception_conf as i_conf
from ryu.lib.dpid import str_to_dpid
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet
from ryu.ofproto import ether

LOGGER = logging.getLogger(__name__)

CONF = cfg.CONF
CONF.import_opt('zookeeper_storage', 'ryu.app.inception_conf')


class InceptionArp(object):
    """Inception Cloud ARP module for handling ARP packets."""

    def __init__(self, inception):
        self.inception = inception

        # name shortcuts
        self.dpset = inception.dpset
        self.dcenter_id = inception.dcenter_id
        self.arp_manager = inception.arp_manager
        self.vmac_manager = inception.vmac_manager
        self.vm_manager = inception.vm_manager
        self.rpc_manager = inception.rpc_manager

    def handle(self, dpid, in_port, arp_header):
        LOGGER.info("Handle ARP packet")

        # ERROR: dst_mac unparsable from arp_header
        src_ip = arp_header.src_ip
        src_mac = arp_header.src_mac

        # Do {IP => MAC} learning
        log_tuple = (src_ip, src_mac)
        if CONF.zookeeper_storage:
            self.inception.create_failover_log(i_conf.ARP_LEARNING, log_tuple)
        self.arp_manager.learn_arp_mapping(src_ip, src_mac, self.rpc_manager)
        if CONF.zookeeper_storage:
            self.inception.delete_failover_log(i_conf.ARP_LEARNING)
        # Process ARP request
        if arp_header.opcode == arp.ARP_REQUEST:
            self._handle_arp_request(dpid, in_port, arp_header)
        # Process ARP reply
        elif arp_header.opcode == arp.ARP_REPLY:
            self._handle_arp_reply(arp_header)

    def create_arp_packet(self, src_mac, dst_mac, dst_ip, src_ip, opcode):
        """Create an Ethernet packet, with ARP packet inside"""

        arp_packet = arp.arp(opcode=opcode,
                              dst_mac=dst_mac,
                              src_mac=src_mac,
                              dst_ip=dst_ip,
                              src_ip=src_ip)
        eth_packet = ethernet.ethernet(ethertype=ether.ETH_TYPE_ARP,
                                        src=src_mac,
                                        dst=dst_mac)
        packet_out = packet.Packet()
        packet_out.add_protocol(eth_packet)
        packet_out.add_protocol(arp_packet)
        packet_out.serialize()

        return packet_out

    def _handle_arp_request(self, dpid, in_port, arp_header):
        """Process ARP request packet."""

        src_ip = arp_header.src_ip
        src_mac = arp_header.src_mac
        dst_ip = arp_header.dst_ip

        LOGGER.info("ARP request: (ip=%s) query (ip=%s)", src_ip, dst_ip)
        src_vmac = self.vmac_manager.get_vm_vmac(src_mac)
        if self.arp_manager.mapping_exist(dst_ip):
            dst_mac = self.arp_manager.get_mac(arp_header.dst_ip)
            dst_vmac = self.vmac_manager.get_vm_vmac(dst_mac)
            dst_dcenter, _, _ = self.vm_manager.get_position(dst_mac)

            LOGGER.info("Cache hit: (dst_ip=%s) <=> (mac=%s, vmac=%s)",
                        dst_ip, dst_mac, dst_vmac)

            # Record the communicating guests and time
            self.vmac_manager.update_query(dst_vmac, src_mac)
            if dst_dcenter == self.dcenter_id:
                self.vmac_manager.update_query(src_vmac, dst_mac)

            # Send arp reply
            src_mac_reply = dst_vmac
            vmac_reply = src_mac
            src_ip_reply = dst_ip
            dst_ip_reply = src_ip
            self.send_arp_reply(src_ip_reply, src_mac_reply,
                                dst_ip_reply, vmac_reply)

    def send_arp_reply(self, src_ip, src_mac, dst_ip, dst_mac):
        """
        Construct an arp reply given the specific arguments
        and send it through switch connecting dst_mac
        """
        pos = self.vm_manager.get_position(dst_mac)
        if pos is not None:
            # If I know to whom to forward back this ARP reply
            _, dst_dpid, dst_port = pos
            # Forward ARP reply
            packet_reply = self.create_arp_packet(src_mac, dst_mac, dst_ip,
                                                  src_ip, arp.ARP_REPLY)
            dst_datapath = self.dpset.get(str_to_dpid(dst_dpid))
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
            LOGGER.info("Send ARP reply of (ip=%s) to (ip=%s): ",
                        src_ip, dst_ip)

    def _handle_arp_reply(self, arp_header):
        """Process ARP reply packet."""

        src_ip = arp_header.src_ip
        src_mac = arp_header.src_mac
        dst_ip = arp_header.dst_ip
        dst_vmac = arp_header.dst_mac

        LOGGER.info("ARP reply: (ip=%s) answer (ip=%s)", src_ip, dst_ip)

        dst_mac = self.arp_manager.get_mac(dst_ip)
        dst_dcenter, _, _ = self.vm_manager.get_position(dst_mac)
        src_vmac = self.vmac_manager.get_vm_vmac(src_mac)

        # Record the communicating guests and time
        self.vmac_manager.update_query(dst_vmac, src_mac)

        if dst_dcenter == self.dcenter_id:
            self.vmac_manager.update_query(src_vmac, dst_mac)
            # An arp reply towards a local server
            self.send_arp_reply(src_ip, src_vmac, dst_ip, dst_mac)

        else:
            # An arp reply towards a remote server in another datacenter
            rpc_client = self.rpc_manager.get_rpc_client(dst_dcenter)
            rpc_client.send_arp_reply(src_ip, src_vmac, dst_ip, dst_mac)
