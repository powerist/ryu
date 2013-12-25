"""
Inception Cloud ARP module
"""
import logging

from oslo.config import cfg

from ryu.lib.dpid import dpid_to_str
from ryu.lib.dpid import str_to_dpid

from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp

LOGGER = logging.getLogger(__name__)

CONF = cfg.CONF
CONF.register_opts([
    cfg.StrOpt('zk_data_path',
               default='/data',
               help="Path for storing all mappings")])


class InceptionArp(object):
    """
    Inception Cloud ARP module for handling ARP packets
    """

    def __init__(self, inception):
        self.inception = inception
        # IP address -> MAC address: mapping from IP address to MAC address
        # of end hosts for address resolution
        # self.ip_to_mac = {}
        self.ip_to_mac_zk = CONF.zk_data_path + '/ip_to_mac'
        self.inception.zk_client.ensure_path(self.ip_to_mac_zk)

    def handle(self, event):
        # process only if it is ARP packet
        msg = event.msg
        whole_packet = packet.Packet(msg.data)

        ethernet_header = whole_packet.get_protocol(ethernet.ethernet)
        if ethernet_header.ethertype != ether.ETH_TYPE_ARP:
            LOGGER.debug("Not an ARP packet. Its type code is %s",
                         ethernet_header.ethertype)
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
        ip_to_mac table
        """
        msg = event.msg

        whole_packet = packet.Packet(msg.data)
        arp_header = whole_packet.get_protocols(arp.arp)[0]
        ip_list = self.inception.zk_client.get_children(self.ip_to_mac_zk)
        if arp_header.src_ip not in ip_list:
            ip_path = self.ip_to_mac_zk + '/' + arp_header.src_ip
            self.inception.zk_client.ensure_path(ip_path)
            self.inception.zk_client.set(ip_path, arp_header.src_mac)
            LOGGER.info("Learn: (ip=%s) => (mac=%s)",
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
        LOGGER.info("ARP request: (ip=%s) query (ip=%s)",
                    arp_header.src_ip, arp_header.dst_ip)
        # If entry not found, broadcast request
        # TODO(Chen): Buffering request? Not needed in a friendly environment
        ip_list = self.inception.zk_client.get_children(self.ip_to_mac_zk)
        if arp_header.dst_ip not in ip_list:
            LOGGER.info("Entry for (ip=%s) not found, broadcast ARP request",
                        arp_header.dst_ip)
            for dpid, dps_datapath in self.inception.dpset.dps.items():
                if dps_datapath.id == datapath.id:
                    continue
                ports = self.inception.dpset.get_ports(dpid)
                # Sift out ports connecting to hosts but vxlan peers
                dpid_path = (
                    self.inception.dpid_to_conns_zk + '/' +
                    dpid_to_str(dpid)
                    )
                remote_ips = (
                    self.inception.zk_client.get_children(dpid_path)
                    )
                remote_ports = []
                for ip in remote_ips:
                    remote_ip_path = dpid_path + '/' + ip
                    remote_port, znode = (
                        self.inception.zk_client.get(remote_ip_path)
                        )
                    remote_ports.append(remote_port)
                vxlan_ports = [int(port_no) for port_no in remote_ports]
                host_ports = [port.port_no for port in ports
                              if port.port_no not in vxlan_ports]
                actions_ports = [ofproto_parser.OFPActionOutput(port)
                                 for port in host_ports]
                dps_datapath.send_msg(
                    ofproto_parser.OFPPacketOut(
                        datapath=dps_datapath,
                        buffer_id=0xffffffff,
                        in_port=ofproto.OFPP_LOCAL,
                        data=msg.data,
                        actions=actions_ports
                        )
                    )
        # Entry exists
        else:
            # setup data forwarding flows
            dst_mac_path = self.ip_to_mac_zk + '/' + arp_header.dst_ip
            result_dst_mac, mac_znode = (
                self.inception.zk_client.get(dst_mac_path)
                )
            self.inception.setup_switch_fwd_flows(arp_header.src_mac,
                                                  result_dst_mac)
            # Construct ARP reply packet and send it to the host
            LOGGER.info("Hit: (dst_ip=%s) <=> (dst_mac=%s)",
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
            datapath.send_msg(
                ofproto_parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=0xffffffff,
                    in_port=ofproto.OFPP_LOCAL,
                    data=packet_reply.data,
                    actions=actions_out
                    )
                )
            LOGGER.info("Answer ARP reply to (host=%s) (mac=%s) on (port=%s) "
                        "on behalf of (ip=%s) (mac=%s)",
                        arp_reply.dst_ip, arp_reply.dst_mac, in_port,
                        arp_reply.src_ip, arp_reply.src_mac)

    def _handle_arp_reply(self, event):
        """
        Process ARP reply packet
        """
        msg = event.msg

        whole_packet = packet.Packet(msg.data)
        arp_header = whole_packet.get_protocol(arp.arp)
        LOGGER.info("ARP reply: (ip=%s) answer (ip=%s)", arp_header.src_ip,
                    arp_header.dst_ip)
        dst_mac_path = (
            self.inception.mac_to_dpid_port_zk + '/' +
            arp_header.dst_mac
            )
        if self.inception.zk_client.exists(dst_mac_path):
            # if I know to whom to forward back this ARP reply
            dst_mac_data_raw, dst_znode = (
                self.inception.zk_client.get(dst_mac_path)
                )
            dst_mac_data = dst_mac_data_raw.split(',')
            dst_dpid_str = dst_mac_data[0]
            dst_dpid = str_to_dpid(dst_dpid_str)
            port_str = dst_mac_data[1]
            port = int(port_str)

            # setup data forwarding flows
            self.inception.setup_switch_fwd_flows(arp_header.src_mac,
                                                  arp_header.dst_mac)
            # forwrad ARP reply
            dst_datapath = self.inception.dpset.get(dst_dpid)
            dst_ofproto_parser = dst_datapath.ofproto_parser
            dst_ofproto = dst_datapath.ofproto
            actions_out = [dst_ofproto_parser.OFPActionOutput(port)]
            dst_datapath.send_msg(
                dst_ofproto_parser.OFPPacketOut(
                    datapath=dst_datapath,
                    buffer_id=0xffffffff,
                    in_port=dst_ofproto.OFPP_LOCAL,
                    data=msg.data,
                    actions=actions_out
                    )
                )
            LOGGER.info("Forward ARP reply from (ip=%s) to (ip=%s) in buffer",
                        arp_header.src_ip, arp_header.dst_ip)
