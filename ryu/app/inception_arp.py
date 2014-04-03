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
import os

from ryu.app import inception_conf as i_conf
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

        # name shortcuts
        self.dpset = inception.dpset
        self.dcenter = inception.dcenter
        self.ip_to_mac = inception.ip_to_mac
        self.dpid_to_conns = inception.dpid_to_conns
        self.mac_to_position = inception.mac_to_position
        self.rpc_client = inception.rpc_client

    def handle(self, dpid, in_port, arp_header, txn):
        LOGGER.info("Handle ARP packet")

        # Do {IP => MAC} learning
        self._do_arp_learning(arp_header, txn)
        # Process ARP request
        if arp_header.opcode == arp.ARP_REQUEST:
            self._handle_arp_request(dpid, arp_header, txn)
        # Process ARP reply
        elif arp_header.opcode == arp.ARP_REPLY:
            self._handle_arp_reply(arp_header, txn)

    def _do_arp_learning(self, arp_header, txn):
        """Learn IP => MAC mapping from a received ARP packet, update
        ip_to_mac table.
        """
        # ERROR: dst_mac unparsable from arp_header
        src_ip = arp_header.src_ip
        src_mac = arp_header.src_mac

        if src_ip not in self.ip_to_mac:
            self.update_arp_mapping(src_ip, src_mac, self.dcenter, txn)
            self.rpc_client.update_arp_mapping(src_ip, src_mac, self.dcenter)

    def update_arp_mapping(self, ip, mac, dcenter, txn):
        zk_path_ip = os.path.join(i_conf.IP_TO_MAC, ip)
        if ip in self.ip_to_mac:
            txn.set_data(zk_path_ip, mac)
        else:
            txn.create(zk_path_ip, mac)
        self.ip_to_mac[ip] = mac
        LOGGER.info("Learn: (ip=%s) => (mac=%s, dcenter=%s)", ip, mac, dcenter)

    def broadcast_arp_request(self, src_ip, src_mac, dst_ip, dpid):
        """
        Construct an ARP request and broadcast it if no record is found to
        reply to the ARP request

        @param dpid: datapath issuing arp request
        """
        if dst_ip not in self.ip_to_mac:
            LOGGER.info("Entry for (ip=%s) not found, broadcast ARP request",
                        dst_ip)

            arp_request = arp.arp(opcode=arp.ARP_REQUEST,
                                  dst_mac='ff:ff:ff:ff:ff:ff',
                                  src_mac=src_mac,
                                  dst_ip=dst_ip,
                                  src_ip=src_ip)
            eth_request = ethernet.ethernet(ethertype=ether.ETH_TYPE_ARP,
                                            src=src_mac,
                                            dst='ff:ff:ff:ff:ff:ff')
            packet_request = packet.Packet()
            packet_request.add_protocol(eth_request)
            packet_request.add_protocol(arp_request)
            packet_request.serialize()

            for dpid, dps_datapath in self.dpset.dps.items():
                dpid = dpid_to_str(dpid)
                if dps_datapath.id == dpid:
                    continue
                ofproto_parser = dps_datapath.ofproto_parser
                ofproto = dps_datapath.ofproto
                ports = self.dpset.get_ports(str_to_dpid(dpid))
                # Sift out ports connecting to guests but tunnel peers
                tunnel_ports = [int(port_no) for port_no in
                                self.dpid_to_conns[dpid].values()]
                guest_ports = [port.port_no for port in ports
                               if port.port_no not in tunnel_ports]
                actions_ports = [ofproto_parser.OFPActionOutput(port)
                                 for port in guest_ports]
                dps_datapath.send_msg(
                    ofproto_parser.OFPPacketOut(
                        datapath=dps_datapath,
                        buffer_id=0xffffffff,
                        in_port=ofproto.OFPP_LOCAL,
                        data=packet_request.data,
                        actions=actions_ports))
        #TODO: why do we need this "else" part?
        else:
            # ARP entry found in local table
            # TODO: Return arp reply
            pass

    def _handle_arp_request(self, dpid, arp_header, txn):
        """Process ARP request packet."""

        src_ip = arp_header.src_ip
        src_mac = arp_header.src_mac
        dst_ip = arp_header.dst_ip

        LOGGER.info("ARP request: (ip=%s) query (ip=%s)", src_ip, dst_ip)
        # If entry not found, broadcast request
        if dst_ip not in self.ip_to_mac:
            self.broadcast_arp_request(src_ip, src_mac, dst_ip, dpid)
            # TODO(chen): Multiple controllers
            self.rpc_client.broadcast_arp_request(src_ip, src_mac, dst_ip,
                                                  dpid)
        else:
            dst_mac = self.ip_to_mac[arp_header.dst_ip]
            LOGGER.info("Cache hit: (dst_ip=%s) <=> (dst_mac=%s)",
                        dst_ip, dst_mac)

            dst_dcenter, _, _ = self.mac_to_position[dst_mac]

            # Setup data forwarding flows
            if dst_dcenter == self.dcenter:
                # Src and dst are in the same datacenter
                self.inception.setup_intra_dcenter_flows(src_mac, dst_mac, txn)
            else:
                # Src and dst are in different datacenters
                self.inception.setup_inter_dcenter_flows(src_mac, dst_mac, txn)
                self.rpc_client.setup_inter_dcenter_flows(dst_mac, src_mac)

            # Send arp reply
            src_mac_reply = dst_mac
            dst_mac_reply = src_mac
            src_ip_reply = dst_ip
            dst_ip_reply = src_ip
            self.send_arp_reply(src_ip_reply, src_mac_reply,
                                dst_ip_reply, dst_mac_reply)

    def send_arp_reply(self, src_ip, src_mac, dst_ip, dst_mac):
        """
        Construct an arp reply given the specific arguments
        and send it through switch connecting dst_mac
        """
        if dst_mac in self.mac_to_position:
            # If I know to whom to forward back this ARP reply
            _, dst_dpid, dst_port = self.mac_to_position[dst_mac]
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

    def _handle_arp_reply(self, arp_header, txn):
        """Process ARP reply packet."""

        src_ip = arp_header.src_ip
        src_mac = arp_header.src_mac
        dst_ip = arp_header.dst_ip
        dst_mac = arp_header.dst_mac

        LOGGER.info("ARP reply: (ip=%s) answer (ip=%s)", src_ip, dst_ip)

        dst_dcenter, _, _ = self.mac_to_position[dst_mac]

        if dst_dcenter == self.dcenter:
            # Setup data forwarding flows
            self.inception.setup_intra_dcenter_flows(src_mac, dst_mac, txn)
            # An arp reply towards a local server
            self.send_arp_reply(src_ip, src_mac, dst_ip, dst_mac)

        else:
            # An arp reply towards a remote server in another datacenter
            self.inception.setup_inter_dcenter_flows(src_mac, dst_mac, txn)
            self.rpc_client.setup_inter_dcenter_flows(dst_mac, src_mac)
            self.rpc_client.send_arp_reply(src_ip, src_mac, dst_ip, dst_mac)
