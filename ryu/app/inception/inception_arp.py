"""
Inception Cloud ARP module
"""
import logging

from ryu.ofproto import ether
from ryu.lib.dpid import dpid_to_str
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.app.inception import priority
from ryu.lib import mac

LOGGER = logging.getLogger(__name__)


class InceptionArp(object):
    """
    Inception Cloud ARP module for handling ARP packets
    """

    def __init__(self, inception):
        self.inception = inception
        # IP address -> MAC address: mapping from IP address to MAC address
        # of end hosts for address resolution
        self.ip_to_mac = {}

    def handle(self, event):
        # process only if it is ARP packet
        msg = event.msg

        whole_packet = packet.Packet(msg.data)
        ethernet_header = whole_packet.get_protocol(ethernet.ethernet)
        if ethernet_header.ethertype != ether.ETH_TYPE_ARP:
            LOGGER.info("This is not an ARP packet")
            print "Its type code is ", ethernet_header.ethertype
            return

        LOGGER.info("Handle ARP packet")
        arp_header = whole_packet.get_protocol(arp.arp)
        # do source learning
        self._do_arp_learning(event)
        # Process ARP request
        if arp_header.opcode == arp.ARP_REQUEST:
            self._handle_arp_request(event)
        # Process ARP reply
        elif arp_header.opcode == arp.ARP_REPLY:
            self._handle_arp_reply(event)

    def _do_arp_learning(self, event):
        """
        Learn IP => MAC mapping from a received ARP packet, update
        self.ip_to_mac table
        """
        msg = event.msg

        whole_packet = packet.Packet(msg.data)
        arp_header = whole_packet.get_protocols(arp.arp)[0]
        if arp_header.src_ip not in self.ip_to_mac:
            self.ip_to_mac[arp_header.src_ip] = arp_header.src_mac
            LOGGER.info("Learn: ip=%s => mac=%s",
                        arp_header.src_ip, arp_header.src_mac)

    def _handle_arp_request(self, event):
        """
        Process ARP request packet
        """
        msg = event.msg
        datapath = msg.datapath
        ofproto_parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']

        whole_packet = packet.Packet(msg.data)
        arp_header = whole_packet.get_protocol(arp.arp)
        LOGGER.info("ARP request: ip=%s query ip=%s",
                    arp_header.src_ip, arp_header.dst_ip)
        # If entry not found, broadcast request
        # TODO(Chen): Buffering request? Not needed in a friendly environment
        if arp_header.dst_ip not in self.ip_to_mac:
            LOGGER.info("Entry for %s not found, broadcast request",
                        arp_header.dst_ip)
            for dpid, dps_datapath in self.inception.dpset.dps.items():
                if dps_datapath.id == datapath.id:
                    continue
                ports = self.inception.dpset.get_ports(dpid)
                # Sift out ports connecting to hosts but vxlan peers
                vxlan_ports = [port_no for port_no in
                    self.inception.dpid_to_conns[dpid].values()]
                host_ports = [port.port_no for port in ports
                    if port.port_no not in vxlan_ports]
                actions_ports = [ofproto_parser.OFPActionOutput(port)
                    for port in host_ports]
                dps_datapath.send_msg(ofproto_parser.OFPPacketOut(
                    datapath=dps_datapath,
                    buffer_id=0xffffffff,
                    in_port=ofproto.OFPP_LOCAL,
                    data=msg.data,
                    actions=actions_ports))
        # Entry exists
        else:
            # setup data forwarding flows
            result_dst_mac = self.ip_to_mac[arp_header.dst_ip]
            self._setup_data_fwd_flows(arp_header.src_mac, result_dst_mac)
            # construct ARP reply packet and send it to the host
            LOGGER.info("Hit: dst_ip=%s, dst_mac=%s",
                        arp_header.dst_ip, result_dst_mac)

            arp_reply = arp.arp(opcode=arp.ARP_REPLY,
                                dst_mac=arp_header.src_mac,
                                src_mac=result_dst_mac,
                                dst_ip=arp_header.src_ip,
                                src_ip=arp_header.dst_ip)
            eth_reply = ethernet.ethernet(ethertype=ether.ETH_TYPE_ARP,
                                          src=arp_reply.src_mac,
                                          dst=arp_reply.dst_mac)
            packet_reply = packet.Packet()
            packet_reply.add_protocol(eth_reply)
            packet_reply.add_protocol(arp_reply)
            packet_reply.serialize()
            actions_out = [ofproto_parser.OFPActionOutput(in_port)]
            datapath.send_msg(ofproto_parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=0xffffffff,
                in_port=ofproto.OFPP_LOCAL,
                data=packet_reply.data,
                actions=actions_out
            ))
            LOGGER.info("Answer ARP reply to host=%s (mac:%s)on port=%s"
                        "on behalf of ip=%s (mac:%s)",
                        arp_reply.dst_ip, arp_reply.dst_mac, in_port,
                        arp_reply.src_ip, arp_reply.src_mac)

    def _handle_arp_reply(self, event):
        """
        Process ARP reply packet
        """
        msg = event.msg

        whole_packet = packet.Packet(msg.data)
        arp_header = whole_packet.get_protocol(arp.arp)
        LOGGER.info("ARP reply: ip=%s answer ip=%s", arp_header.src_ip,
                    arp_header.dst_ip)
        # if I know to whom to forward back this ARP reply
        if arp_header.dst_mac in self.inception.mac_to_dpid_port:
            dst_dpid, port = (self.inception.
                mac_to_dpid_port[arp_header.dst_mac])
            # setup data forwarding flows
            self._setup_data_fwd_flows(arp_header.src_mac, arp_header.dst_mac)
            # forwrad ARP reply
            dst_datapath = self.inception.dpset.get(dst_dpid)
            dst_ofproto_parser = dst_datapath.ofproto_parser
            dst_ofproto = dst_datapath.ofproto
            actions_out = [dst_ofproto_parser.OFPActionOutput(port)]
            dst_datapath.send_msg(dst_ofproto_parser.OFPPacketOut(
                datapath=dst_datapath,
                buffer_id=0xffffffff,
                in_port=dst_ofproto.OFPP_LOCAL,
                data=msg.data,
                actions=actions_out
            ))
            LOGGER.info("Forward ARP reply from ip=%s to ip=%s in buffer",
                        arp_header.src_ip, arp_header.dst_ip)

    def _setup_data_fwd_flows(self, src_mac, dst_mac):
        """
        Given two MAC addresses, set up flows on their connected switches
        towards each other, so that they can forward packets between each other
        """
        (src_dpid, src_port) = (self.inception.mac_to_dpid_port[src_mac])
        (dst_dpid, dst_port) = (self.inception.mac_to_dpid_port[dst_mac])

        # If src_dpid == dst_dpid, no need to set up flows
        if src_dpid == dst_dpid:
            return

        src_ip = self.inception.dpid_to_ip[src_dpid]
        dst_ip = self.inception.dpid_to_ip[dst_dpid]
        src_fwd_port = self.inception.dpid_to_conns[src_dpid][dst_ip]
        dst_fwd_port = self.inception.dpid_to_conns[dst_dpid][src_ip]
        src_datapath = self.inception.dpset.get(src_dpid)
        dst_datapath = self.inception.dpset.get(dst_dpid)
        src_ofproto = src_datapath.ofproto
        dst_ofproto = dst_datapath.ofproto
        src_ofproto_parser = src_datapath.ofproto_parser
        dst_ofproto_parser = dst_datapath.ofproto_parser
        if (src_dpid, dst_mac) not in self.inception.unicast_rules:
            actions_fwd = [src_ofproto_parser.OFPActionOutput(src_fwd_port)]
            instructions_fwd = [src_datapath.ofproto_parser.
                OFPInstructionActions(src_ofproto.OFPIT_APPLY_ACTIONS,
                                      actions_fwd)]
            src_datapath.send_msg(src_ofproto_parser.OFPFlowMod(
                datapath=src_datapath,
                match=src_ofproto_parser.OFPMatch(eth_dst=dst_mac),
                cookie=0,
                command=src_ofproto.OFPFC_ADD,
                priority=priority.DATA_FWD,
                flags=src_ofproto.OFPFF_SEND_FLOW_REM,
                instructions=instructions_fwd
            ))
            self.inception.unicast_rules.append((src_dpid, dst_mac))
            LOGGER.info("Setup forward flow on switch=%s towards mac=%s",
                        dpid_to_str(src_dpid), dst_mac)

        if (dst_dpid, src_mac) not in self.inception.unicast_rules:
            actions_dst = [dst_ofproto_parser.OFPActionOutput(dst_fwd_port)]
            instructions_dst = [dst_datapath.ofproto_parser.
                OFPInstructionActions(dst_ofproto.OFPIT_APPLY_ACTIONS,
                                      actions_dst)]
            dst_datapath.send_msg(dst_ofproto_parser.OFPFlowMod(
                datapath=dst_datapath,
                match=dst_ofproto_parser.OFPMatch(eth_dst=src_mac),
                cookie=0, command=dst_ofproto.OFPFC_ADD,
                priority=priority.DATA_FWD,
                flags=dst_ofproto.OFPFF_SEND_FLOW_REM,
                instructions=instructions_dst
                ))
            self.inception.unicast_rules.append((dst_dpid, src_mac))
            LOGGER.info("Setup forward flow on switch=%s towards mac=%s",
                        dpid_to_str(dst_dpid), src_mac)
