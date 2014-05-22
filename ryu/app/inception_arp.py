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
import time

from oslo.config import cfg

from ryu.app import inception_conf as i_conf
from ryu.lib import mac
from ryu.lib.dpid import dpid_to_str
from ryu.lib.dpid import str_to_dpid
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet
from ryu.ofproto import ether

LOGGER = logging.getLogger(__name__)

CONF = cfg.CONF
CONF.import_opt('arp_bcast', 'ryu.app.inception_conf')


class InceptionArp(object):
    """Inception Cloud ARP module for handling ARP packets."""

    def __init__(self, inception):
        self.inception = inception

        # name shortcuts
        self.zk = inception.zk
        self.dpset = inception.dpset
        self.dcenter_id = inception.dcenter_id
        self.single_dcenter = inception.single_dcenter
        self.ip_to_mac = inception.ip_to_mac
        self.mac_to_ip = inception.mac_to_ip
        self.dpid_to_conns = inception.dpid_to_conns
        self.dpid_to_vmac = inception.dpid_to_vmac
        self.mac_to_position = inception.mac_to_position
        self.vmac_to_queries = inception.vmac_to_queries
        if not self.single_dcenter:
            self.dcenter_to_rpc = inception.dcenter_to_rpc

    def handle(self, dpid, in_port, arp_header):
        LOGGER.info("Handle ARP packet")

        # ERROR: dst_mac unparsable from arp_header
        src_ip = arp_header.src_ip
        src_mac = arp_header.src_mac

        # Do {IP => MAC} learning
        log_tuple = (src_ip, src_mac)
        self.inception.create_failover_log(i_conf.ARP_LEARNING, log_tuple)
        self.do_arp_learning(src_ip, src_mac)
        self.inception.delete_failover_log(i_conf.ARP_LEARNING)
        # Process ARP request
        if arp_header.opcode == arp.ARP_REQUEST:
            self._handle_arp_request(dpid, in_port, arp_header)
        # Process ARP reply
        elif arp_header.opcode == arp.ARP_REPLY:
            self._handle_arp_reply(arp_header)

    def do_arp_learning(self, src_ip, src_mac):
        """Learn IP => MAC mapping from a received ARP packet, update
        ip_to_mac and mac_to_ip table.
        """
        if (src_ip, src_mac) in self.ip_to_mac.items():
            # Duplicate arp learning
            return

        if not self.single_dcenter:
            for rpc_client in self.dcenter_to_rpc.values():
                rpc_client.update_arp_mapping(src_ip, src_mac, self.dcenter_id)
        self.update_arp_mapping(src_ip, src_mac, self.dcenter_id)

    def update_arp_mapping(self, ip, mac, dcenter):
        zk_path_ip = os.path.join(i_conf.IP_TO_MAC, ip)
        if ip in self.ip_to_mac:
            self.zk.set_data(zk_path_ip, mac)
        else:
            self.zk.create(zk_path_ip, mac)
        self.ip_to_mac[ip] = mac
        self.mac_to_ip[mac] = ip
        LOGGER.info("Update: (ip=%s) => (mac=%s, dcenter=%s)",
                    ip, mac, dcenter)

    def broadcast_arp_request(self, src_ip, src_mac, dst_ip, dpid):
        """
        Construct an ARP request and broadcast it if no record is found to
        reply to the ARP request

        @param dpid: datapath issuing arp request
        """
        if dst_ip not in self.ip_to_mac:
            LOGGER.info("Entry for (ip=%s) not found, broadcast ARP request",
                        dst_ip)

            packet_request = self.create_arp_packet(src_mac,
                                                    mac.BROADCAST_STR,
                                                    dst_ip,
                                                    src_ip,
                                                    arp.ARP_REQUEST)
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
        _, _, _, src_vmac = self.mac_to_position[src_mac]
        if dst_ip not in self.ip_to_mac:
            if CONF.arp_bcast:
                self.broadcast_arp_request(src_ip, src_vmac, dst_ip, dpid)
                if not self.single_dcenter:
                    for rpc_client in self.dcenter_to_rpc.values():
                        rpc_client.broadcast_arp_request(src_ip, src_vmac,
                                                         dst_ip, dpid)
        else:
            dst_mac = self.ip_to_mac[arp_header.dst_ip]
            dst_dcenter, _, _, dst_vmac = self.mac_to_position[dst_mac]

            LOGGER.info("Cache hit: (dst_ip=%s) <=> (mac=%s, vmac=%s)",
                        dst_ip, dst_mac, dst_vmac)

            # Record the communicating guests and time
            timestamp = time.time()
            self.vmac_to_queries[dst_vmac][src_mac] = timestamp
            if dst_dcenter == self.dcenter_id:
                self.vmac_to_queries[src_vmac][dst_mac] = timestamp

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
        if dst_mac in self.mac_to_position:
            # If I know to whom to forward back this ARP reply
            _, dst_dpid, dst_port, _ = self.mac_to_position[dst_mac]
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

        dst_mac = self.ip_to_mac[dst_ip]
        dst_dcenter, _, _, _ = self.mac_to_position[dst_mac]
        _, _, _, src_vmac = self.mac_to_position[src_mac]

        # Record the communicating guests and time
        timestamp = time.time()
        self.vmac_to_queries[dst_vmac][src_mac] = timestamp

        if dst_dcenter == self.dcenter_id:
            self.vmac_to_queries[src_vmac][dst_mac] = timestamp
            # An arp reply towards a local server
            self.send_arp_reply(src_ip, src_vmac, dst_ip, dst_mac)

        else:
            # An arp reply towards a remote server in another datacenter
            rpc_client_dst = self.dcenter_to_rpc[dst_dcenter]
            rpc_client_dst.send_arp_reply(src_ip, src_vmac, dst_ip, dst_mac)
