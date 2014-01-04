"""
Inception Cloud DHCP module
"""
import logging

from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.dpid import dpid_to_str
from ryu.lib.dpid import str_to_dpid

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp

LOGGER = logging.getLogger(__name__)

DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68


class InceptionDhcp(object):
    """
    Inception Cloud DHCP module for handling DHCP packets
    """

    def __init__(self, inception):
        self.inception = inception
        # the switch to which DHCP server connects
        self.server_switch = None
        # the port of switch on which DHCP server connects
        self.server_port = None

    def update_server(self, switch, port):
        if self.server_port is not None and self.server_switch is not None:
            LOGGER.warning("Found more than one DHCP server. Ignore others!")
            return
        self.server_switch = switch
        self.server_port = port

    def handle(self, event):
        # process only if it is DHCP packet
        msg = event.msg
        whole_packet = packet.Packet(msg.data)

        ethernet_header = whole_packet.get_protocol(ethernet.ethernet)
        if ethernet_header.ethertype != ether.ETH_TYPE_IP:
            LOGGER.debug('not an Ethernet IP packet')
            return
        ip_header = whole_packet.get_protocol(ipv4.ipv4)
        if ip_header.proto != inet.IPPROTO_UDP:
            LOGGER.debug('not an IPv4 packet')
            return
        udp_header = whole_packet.get_protocol(udp.udp);
        if udp_header.src_port not in (DHCP_CLIENT_PORT, DHCP_SERVER_PORT):
            LOGGER.debug('not an UDP port-%s/%s packet', DHCP_CLIENT_PORT,
                         DHCP_SERVER_PORT)
            return

        LOGGER.info("Handle DHCP packet")
        if self.server_switch is None or self.server_port is None:
            LOGGER.warning("No DHCP server has been found!")
            return

        # A packet received from client. Find out the switch connected
        # to dhcp server and forward the packet
        if udp_header.src_port == DHCP_CLIENT_PORT:
            LOGGER.info("Forward DHCP message to server at (switch=%s) "
                        "(port=%s)", dpid_to_str(self.server_switch),
                        self.server_port)
            datapath = self.inception.dpset.get(self.server_switch)
            action_out = [
                datapath.ofproto_parser.OFPActionOutput(self.server_port)
                ]
            datapath.send_msg(
                datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=0xffffffff,
                    in_port=datapath.ofproto.OFPP_LOCAL,
                    data=msg.data,
                    actions=action_out)
                )
        # A packet received from server. Find out the mac address of
        # the client and forward the packet to it.
        elif udp_header.src_port == DHCP_SERVER_PORT:
            mac_path = (self.inception.mac_to_dpid_port_zk + '/' +
                ethernet_header.dst)
            mac_data_raw, data_znode = self.inception.zk_client.get(mac_path)
            mac_data = mac_data_raw.split(',')
            dpid_str = mac_data[0]
            dpid = str_to_dpid(dpid_str)
            port_str = mac_data[1]
            port = int(port_str)
            LOGGER.info("Forward DHCP message to client (mac=%s) at "
                        "(switch=%s) (port=%s)", ethernet_header.dst,
                        dpid_to_str(dpid), port)
            datapath = self.inception.dpset.get(dpid)
            action_out = [datapath.ofproto_parser.OFPActionOutput(port)]
            datapath.send_msg(
                datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=0xffffffff,
                    in_port=datapath.ofproto.OFPP_LOCAL,
                    data=msg.data,
                    actions=action_out
                    )
                )
