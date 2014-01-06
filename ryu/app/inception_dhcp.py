"""
Inception Cloud DHCP module
"""

import logging
import os

from oslo.config import cfg

from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.dpid import str_to_dpid
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp

LOGGER = logging.getLogger(__name__)

CONF = cfg.CONF
CONF.import_opt('zk_data', 'ryu.app.inception_conf')

DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68


class InceptionDhcp(object):
    """
    Inception Cloud DHCP module for handling DHCP packets
    """

    # Path in ZooKeeper, under which records the switch to which DHCP
    # server connects
    #
    SERVER_DPID = os.path.join(CONF.zk_data, 'dhcp_server_dpid')

    # Path in ZooKeeper, under which records the port of switch on
    # which DHCP server connects
    #
    SERVER_PORT = os.path.join(CONF.zk_data, 'dhcp_server_port')

    def __init__(self, inception):
        self.inception = inception
        self.inception.zk.ensure_path(self.SERVER_DPID)
        self.inception.zk.ensure_path(self.SERVER_PORT)

    def update_server(self, dpid, port):
        server_dpid, _ = self.inception.zk.get(self.SERVER_DPID)
        server_port, _ = self.inception.zk.get(self.SERVER_PORT)
        if server_port and server_dpid:
            LOGGER.warning("Found more than one DHCP server. Ignore others!")
            return
        self.inception.zk.set(self.SERVER_DPID, dpid)
        self.inception.zk.set(self.SERVER_PORT, str(port))

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
        udp_header = whole_packet.get_protocol(udp.udp)
        if udp_header.src_port not in (DHCP_CLIENT_PORT, DHCP_SERVER_PORT):
            LOGGER.debug('not an UDP port-%s/%s packet', DHCP_CLIENT_PORT,
                         DHCP_SERVER_PORT)
            return

        server_dpid, _ = self.inception.zk.get(self.SERVER_DPID)
        server_port, _ = self.inception.zk.get(self.SERVER_PORT)

        LOGGER.info("Handle DHCP packet")
        if not server_dpid or not server_port:
            LOGGER.warning("No DHCP server has been found!")
            return

        # A packet received from client. Find out the switch connected
        # to dhcp server and forward the packet
        if udp_header.src_port == DHCP_CLIENT_PORT:
            LOGGER.info("Forward DHCP message to server at (switch=%s) "
                        "(port=%s)", server_dpid, server_port)
            datapath = self.inception.dpset.get(str_to_dpid(server_dpid))
            action_out = [
                datapath.ofproto_parser.OFPActionOutput(
                    int(server_port))]
            datapath.send_msg(
                datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=0xffffffff,
                    in_port=datapath.ofproto.OFPP_LOCAL,
                    data=msg.data,
                    actions=action_out))
        # A packet received from server. Find out the mac address of
        # the client and forward the packet to it.
        elif udp_header.src_port == DHCP_SERVER_PORT:
            dpid_port, _ = self.inception.zk.get(os.path.join(
                self.inception.MAC_TO_DPID_PORT, ethernet_header.dst))
            dpid, port = dpid_port.split(',')
            LOGGER.info("Forward DHCP message to client (mac=%s) at "
                        "(switch=%s) (port=%s)", ethernet_header.dst,
                        dpid, port)
            datapath = self.inception.dpset.get(str_to_dpid(dpid))
            action_out = [datapath.ofproto_parser.OFPActionOutput(int(port))]
            datapath.send_msg(
                datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=0xffffffff,
                    in_port=datapath.ofproto.OFPP_LOCAL,
                    data=msg.data,
                    actions=action_out))
