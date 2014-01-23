"""
Inception Cloud SDN controller
"""

import logging
import os

from oslo.config import cfg
from kazoo.client import KazooClient

from ryu import log
from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.controller import handler
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib import mac
from ryu.lib.dpid import dpid_to_str
from ryu.lib.dpid import str_to_dpid
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.app.inception_arp import InceptionArp
from ryu.app.inception_dhcp import InceptionDhcp
from ryu.app.inception_dhcp import DHCP_CLIENT_PORT
from ryu.app.inception_dhcp import DHCP_SERVER_PORT
from ryu.app.inception_util import tuple_to_zk_data
from ryu.app.inception_util import zk_data_to_tuple
from ryu.app.inception_conf import DPID_TO_IP
from ryu.app.inception_conf import DPID_TO_CONNS
from ryu.app.inception_conf import MAC_TO_DPID_PORT
from ryu.app.inception_conf import MAC_TO_FLOWS
from ryu.app.inception_conf import IP_TO_MAC
from ryu.app.inception_conf import DHCP_SWITCH_DPID
from ryu.app.inception_conf import DHCP_SWITCH_PORT

import ryu.app.inception_priority as priority

LOGGER = logging.getLogger(__name__)

CONF = cfg.CONF
CONF.import_opt('zk_servers', 'ryu.app.inception_conf')
CONF.import_opt('zk_data', 'ryu.app.inception_conf')
CONF.import_opt('zk_failover', 'ryu.app.inception_conf')
CONF.import_opt('zk_log_level', 'ryu.app.inception_conf')
CONF.import_opt('ip_prefix', 'ryu.app.inception_conf')


class Inception(app_manager.RyuApp):
    """
    Inception Cloud SDN controller
    """

    # Default built-in Ryu module, manage all connected switches
    #
    # {dpid => datapath}
    _CONTEXTS = {
        'dpset': dpset.DPSet
    }

    # Default OpenFlow version
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    # Default packet len
    MAX_LEN = 65535
    SWITCH_NUMBER = 4

    def __init__(self, *args, **kwargs):
        super(Inception, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']

        # all network data (in the form of dict) is stored in ZooKeeper
        zk_logger = logging.getLogger('kazoo')
        zk_log_level = log.LOG_LEVELS[CONF.zk_log_level]
        zk_logger.setLevel(zk_log_level)
        zk_console_handler = logging.StreamHandler()
        zk_console_handler.setLevel(zk_log_level)
        zk_console_handler.setFormatter(CONF.log_formatter)
        zk_logger.addHandler(zk_console_handler)
        self.zk = KazooClient(hosts=CONF.zk_servers, logger=zk_logger)
        self.zk.start()
        self.zk.ensure_path(CONF.zk_data)
        self.zk.ensure_path(CONF.zk_failover)
        self.zk.ensure_path(DPID_TO_IP)
        self.zk.ensure_path(DPID_TO_CONNS)
        self.zk.ensure_path(MAC_TO_DPID_PORT)
        self.zk.ensure_path(MAC_TO_FLOWS)
        self.zk.ensure_path(IP_TO_MAC)
        self.zk.ensure_path(DHCP_SWITCH_DPID)
        self.zk.ensure_path(DHCP_SWITCH_PORT)
        self.switch_count = 0

        ## Inception relevent modules
        # ARP
        self.inception_arp = InceptionArp(self)
        # DHCP
        self.inception_dhcp = InceptionDhcp(self)

    @handler.set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def switch_connection_handler(self, event):
        """
        Handle when a switch event is received
        """
        datapath = event.dp
        dpid = dpid_to_str(datapath.id)
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser

        # A new switch connects
        if event.enter:
            self.switch_count += 1
            socket = datapath.socket
            ip, port = socket.getpeername()
            host_ports = []

            # Update {dpid => ip}
            ip_path = os.path.join(DPID_TO_IP, dpid)
            self.zk.ensure_path(ip_path)
            self.zk.set(ip_path, ip)
            LOGGER.info("Add: (switch=%s) -> (ip=%s)", dpid, ip)

            # Collect port information.  Sift out ports connecting peer
            # switches and store them under DPID_TO_CONNS
            for port in event.ports:
                # TODO(changbl): Use OVSDB. Parse the port name to get the IP
                # address of remote rVM to which the bridge builds a
                # VXLAN. E.g., obr1_184-53 => CONF.ip_prefix.184.53. Only
                # store the port connecting remote rVM.
                port_no = str(port.port_no)
                if port.name.startswith('obr') and '_' in port.name:
                    _, ip_suffix = port.name.split('_')
                    ip_suffix = ip_suffix.replace('-', '.')
                    peer_ip = '.'.join((CONF.ip_prefix, ip_suffix))
                    zk_path = os.path.join(DPID_TO_CONNS, dpid, peer_ip)
                    self.zk.ensure_path(zk_path)
                    self.zk.set(zk_path, port_no)
                    LOGGER.info("Add: (switch=%s, peer_ip=%s) -> (port=%s)",
                                dpid, peer_ip, port_no)
                elif port.name == 'eth_dhcp':
                    LOGGER.info("DHCP server is found!")
                    self.inception_dhcp.update_server(dpid, port_no)
                else:
                    # Store the port connecting local hosts
                    host_ports.append(port_no)

            # Set up one flow for ARP messages
            # Intercepts all ARP packets and send them to the controller
            actions_arp = [ofproto_parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                self.MAX_LEN)]
            instruction_arp = [datapath.ofproto_parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions_arp)]
            datapath.send_msg(
                ofproto_parser.OFPFlowMod(
                    datapath=datapath,
                    match=ofproto_parser.OFPMatch(
                        eth_type=ether.ETH_TYPE_ARP),
                    priority=priority.ARP,
                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                    cookie=0,
                    command=ofproto.OFPFC_ADD,
                    instructions=instruction_arp))

            # Set up two flows for DHCP messages
            # (1) Intercept all DHCP request packets and send to the controller
            actions_dhcp = [ofproto_parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                self.MAX_LEN)]
            instruction_dhcp = [datapath.ofproto_parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions_dhcp)]
            datapath.send_msg(
                ofproto_parser.OFPFlowMod(
                    datapath=datapath,
                    match=ofproto_parser.OFPMatch(
                        eth_type=ether.ETH_TYPE_IP,
                        ip_proto=inet.IPPROTO_UDP,
                        udp_src=DHCP_CLIENT_PORT),
                    priority=priority.DHCP,
                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                    cookie=0,
                    command=ofproto.OFPFC_ADD,
                    instructions=instruction_dhcp))
            # (2) Intercept all DHCP reply packets and send to the controller
            actions_dhcp = [ofproto_parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                Inception.MAX_LEN)]
            instruction_dhcp = [datapath.ofproto_parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions_dhcp)]
            datapath.send_msg(
                ofproto_parser.OFPFlowMod(
                    datapath=datapath,
                    match=ofproto_parser.OFPMatch(
                        eth_type=ether.ETH_TYPE_IP,
                        ip_proto=inet.IPPROTO_UDP,
                        udp_src=DHCP_SERVER_PORT),
                    priority=priority.DHCP,
                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                    cookie=0,
                    command=ofproto.OFPFC_ADD,
                    instructions=instruction_dhcp))

            # Set up two parts of flows for broadcast messages
            # (1) Broadcast messages from each local port: forward to all
            # (other) ports
            for port_no in host_ports:
                actions_bcast_out = [
                    ofproto_parser.OFPActionOutput(
                        ofproto.OFPP_ALL)]
                instructions_bcast_out = [
                    datapath.ofproto_parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS,
                        actions_bcast_out)]
                datapath.send_msg(
                    ofproto_parser.OFPFlowMod(
                        datapath=datapath,
                        match=ofproto_parser.OFPMatch(
                            in_port=int(port_no),
                            eth_dst=mac.BROADCAST_STR),
                        priority=priority.HOST_BCAST,
                        flags=ofproto.OFPFF_SEND_FLOW_REM,
                        cookie=0,
                        command=ofproto.OFPFC_ADD,
                        instructions=instructions_bcast_out))
            # (2) Broadcast messages from each (tunnel) port: forward to all
            # local ports. Since priority.SWITCH_BCAST < priority.HOST_BCAST,
            # this guarantees that only tunnel-port message will trigger this
            # flow
            actions_bcast_in = [
                ofproto_parser.OFPActionOutput(port=int(port_no))
                for port_no in host_ports]
            instruction_bcast_in = [
                datapath.ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    actions_bcast_in)]
            datapath.send_msg(
                ofproto_parser.OFPFlowMod(
                    datapath=datapath,
                    match=ofproto_parser.OFPMatch(
                        eth_dst=mac.BROADCAST_STR),
                    priority=priority.SWITCH_BCAST,
                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                    cookie=0,
                    command=ofproto.OFPFC_ADD,
                    instructions=instruction_bcast_in))

            # Finally, setup a default flow
            # Process via normal L2/L3 legacy switch configuration
            actions_norm = [
                ofproto_parser.OFPActionOutput(
                    ofproto.OFPP_NORMAL)]
            instruction_norm = [
                datapath.ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    actions_norm)]
            datapath.send_msg(
                ofproto_parser.OFPFlowMod(
                    datapath=datapath,
                    match=ofproto_parser.OFPMatch(),
                    priority=priority.NORMAL,
                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                    cookie=0,
                    command=ofproto.OFPFC_ADD,
                    instructions=instruction_norm))

            if self.switch_count == Inception.SWITCH_NUMBER:
                # Do failover
                self._do_failover()

        # A switch disconnects
        else:
            transaction = self.zk.transaction()
            ip, _ = self.zk.get(os.path.join(DPID_TO_IP, dpid))

            # Delete switch's mapping from switch dpid to remote IP address
            transaction.delete(os.path.join(DPID_TO_IP, dpid))
            LOGGER.info("Del: (switch=%s) -> (ip=%s)", dpid, ip)

            # Delete the switch's all connection info
            transaction.delete(os.path.join(DPID_TO_CONNS, dpid),
                               recursive=True)
            LOGGER.info("Del: (switch=%s) dpid_to_conns", dpid)

            # Delete all connected hosts
            for child in self.zk.get_children(MAC_TO_DPID_PORT):
                zk_path = os.path.join(MAC_TO_DPID_PORT, child)
                dpid_port, _ = self.zk.get(zk_path)
                if dpid_port.startswith(dpid):
                    transaction.delete(zk_path)
            LOGGER.info("Del: (switch=%s) mac_to_dpid_port", dpid)

            # Delete all rules trackings
            for child in self.zk.get_children(MAC_TO_FLOWS):
                if dpid in self.zk.get_children(
                        os.path.join(MAC_TO_FLOWS, child)):
                    transaction.delete(os.path.join(MAC_TO_FLOWS, child, dpid))
            LOGGER.info("Del: (switch=%s) mac_to_flows", dpid)
            transaction.commit()

    def _do_failover(self):
        """
        Check if any work is left by previous controller.
        If so, continue the unfinished work.
        """
        failover_node = self.zk.get_children(CONF.zk_failover)
        for znode_unicode in failover_node:
            znode = znode_unicode.encode('Latin-1')
            log_path = os.path.join(CONF.zk_failover, znode)
            data, _ = self.zk.get(log_path)
            (dpid, in_port) = zk_data_to_tuple(znode)
            transaction = self.zk.transaction()
            self._process_packet_in(dpid, in_port, data, transaction)
            transaction.delete(log_path)
            transaction.commit()

    @handler.set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def packet_in_handler(self, event):
        """
        Handle when a packet is received
        """
        msg = event.msg
        datapath = msg.datapath
        dpid = dpid_to_str(datapath.id)
        in_port = str(msg.match['in_port'])

        # Failover logging
        znode_name = tuple_to_zk_data((dpid, in_port))
        log_path = os.path.join(CONF.zk_failover, znode_name)
        self.zk.create(log_path, msg.data)

        transaction = self.zk.transaction()
        self._process_packet_in(dpid, in_port, msg.data, transaction)
        transaction.delete(log_path)
        transaction.commit()

    def _process_packet_in(self, dpid, in_port, data, transaction):
        """
        Process raw data received from dpid through in_port
        """
        whole_packet = packet.Packet(data)
        ethernet_header = whole_packet.get_protocol(ethernet.ethernet)
        ethernet_src = ethernet_header.src

        # do source learning
        self._do_source_learning(dpid, in_port, ethernet_src, transaction)
        # handle ARP packet if it is
        if ethernet_header.ethertype == ether.ETH_TYPE_ARP:
            arp_header = whole_packet.get_protocol(arp.arp)
            self.inception_arp.handle(dpid, in_port, arp_header, transaction)
        # handle DHCP packet if it is
        # self.inception_dhcp.handle(event)

    def _do_source_learning(self, dpid, in_port, ethernet_src, transaction):
        """
        Learn MAC => (switch dpid, switch port) mapping from a packet,
        update data in MAC_TO_DPID_PORT. Also set up flow table for
        forwarding broadcast message
        """
        datapath = self.dpset.get(str_to_dpid(dpid))
        ofproto_parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        if ethernet_src not in self.zk.get_children(MAC_TO_DPID_PORT):
            dpid_port = tuple_to_zk_data((dpid, in_port))
            transaction.create(os.path.join(MAC_TO_DPID_PORT, ethernet_src),
                           dpid_port)
            LOGGER.info("Learn: (mac=%s) => (switch=%s, port=%s)",
                        ethernet_src, dpid, in_port)
            # Set unicast flow to ethernet_src
            actions_unicast = [ofproto_parser.OFPActionOutput(int(in_port))]
            instructions_unicast = [
                datapath.ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    actions_unicast)]
            datapath.send_msg(
                ofproto_parser.OFPFlowMod(
                    datapath=datapath,
                    match=ofproto_parser.OFPMatch(
                        eth_dst=ethernet_src),
                    cookie=0,
                    command=ofproto.OFPFC_ADD,
                    priority=priority.DATA_FWD,
                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                    instructions=instructions_unicast))
            transaction.create(os.path.join(MAC_TO_FLOWS, ethernet_src))
            transaction.create(os.path.join(MAC_TO_FLOWS, ethernet_src, dpid))
            LOGGER.info("Setup local forward flow on (switch=%s) towards "
                        "(mac=%s)", dpid, ethernet_src)
        else:
            dpid_port_record, _ = self.zk.get(os.path.join(
                MAC_TO_DPID_PORT, ethernet_src))
            dpid_record, _ = zk_data_to_tuple(dpid_port_record)
            # The host's switch changes, e.g., due to a VM live migration
            if dpid_record != dpid:
                ip, _ = self.zk.get(os.path.join(DPID_TO_IP, dpid))
                dpid_port_new = tuple_to_zk_data((dpid, in_port))
                transaction.set(os.path.join(MAC_TO_DPID_PORT, ethernet_src),
                            dpid_port_new)
                LOGGER.info("Update: (mac=%s) => (switch=%s, port=%s)",
                            ethernet_src, dpid, in_port)

                # Add a flow on new datapath towards ethernet_src
                flow_command = None
                zk_path = os.path.join(MAC_TO_FLOWS, ethernet_src, dpid)
                if self.zk.exists(zk_path):
                    flow_command = ofproto.OFPFC_MODIFY_STRICT
                else:
                    flow_command = ofproto.OFPFC_ADD
                    transaction.create(zk_path)
                actions_inport = [ofproto_parser.OFPActionOutput(int(in_port))]
                instructions_inport = [
                    datapath.ofproto_parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS,
                        actions_inport)]
                datapath.send_msg(
                    ofproto_parser.OFPFlowMod(
                        datapath=datapath,
                        match=ofproto_parser.OFPMatch(
                            eth_dst=ethernet_src),
                        cookie=0,
                        command=flow_command,
                        priority=priority.DATA_FWD,
                        flags=ofproto.OFPFF_SEND_FLOW_REM,
                        instructions=instructions_inport))
                operation = ('Add' if flow_command == ofproto.OFPFC_ADD
                             else 'Modify')
                LOGGER.info("%s local forward flow on (switch=%s) towards "
                            "(mac=%s)", operation, dpid, ethernet_src)

                # Mofidy flows on all other datapaths contacting ethernet_src
                for remote_dpid in self.zk.get_children(
                        os.path.join(MAC_TO_FLOWS, ethernet_src)):
                    if remote_dpid == dpid:
                        continue

                    remote_datapath = self.dpset.get(str_to_dpid(remote_dpid))
                    remote_fwd_port, _ = self.zk.get(os.path.join(
                        DPID_TO_CONNS, remote_dpid, ip))
                    actions_remote = [ofproto_parser.OFPActionOutput(
                        int(remote_fwd_port))]
                    instructions_remote = [
                        datapath.ofproto_parser.OFPInstructionActions(
                            ofproto.OFPIT_APPLY_ACTIONS,
                            actions_remote)]
                    remote_datapath.send_msg(
                        ofproto_parser.OFPFlowMod(
                            datapath=remote_datapath,
                            match=ofproto_parser.OFPMatch(
                                eth_dst=ethernet_src),
                            cookie=0,
                            command=ofproto.OFPFC_MODIFY_STRICT,
                            priority=priority.DATA_FWD,
                            flags=ofproto.OFPFF_SEND_FLOW_REM,
                            instructions=instructions_remote))
                    LOGGER.info("Update remote forward flow on (switch=%s) "
                                "towards (mac=%s)", remote_dpid, ethernet_src)

    def setup_switch_fwd_flows(self, src_mac, src_dpid, dst_mac, transaction):
        """
        Given two MAC addresses, set up flows on their connected switches
        towards each other, so that the two can forward packets in between
        """
        dst_dpid_port, _ = self.zk.get(os.path.join(
            MAC_TO_DPID_PORT, dst_mac))
        dst_dpid, _ = zk_data_to_tuple(dst_dpid_port)

        # If src_dpid == dst_dpid, no need to set up flows
        if src_dpid == dst_dpid:
            return

        src_ip, _ = self.zk.get(os.path.join(DPID_TO_IP, src_dpid))
        dst_ip, _ = self.zk.get(os.path.join(DPID_TO_IP, dst_dpid))
        src_fwd_port, _ = self.zk.get(os.path.join(
            DPID_TO_CONNS, src_dpid, dst_ip))
        dst_fwd_port, _ = self.zk.get(os.path.join(
            DPID_TO_CONNS, dst_dpid, src_ip))
        src_datapath = self.dpset.get(str_to_dpid(src_dpid))
        dst_datapath = self.dpset.get(str_to_dpid(dst_dpid))
        src_ofproto = src_datapath.ofproto
        dst_ofproto = dst_datapath.ofproto
        src_ofproto_parser = src_datapath.ofproto_parser
        dst_ofproto_parser = dst_datapath.ofproto_parser

        # Setup a flow on the src switch
        if not self.zk.exists(os.path.join(MAC_TO_FLOWS, dst_mac, src_dpid)):
            actions_src = [src_ofproto_parser.OFPActionOutput(
                int(src_fwd_port))]
            instructions_src = [
                src_datapath.ofproto_parser.OFPInstructionActions(
                    src_ofproto.OFPIT_APPLY_ACTIONS,
                    actions_src)]
            src_datapath.send_msg(
                src_ofproto_parser.OFPFlowMod(
                    datapath=src_datapath,
                    match=src_ofproto_parser.OFPMatch(
                        eth_dst=dst_mac),
                    cookie=0,
                    command=src_ofproto.OFPFC_ADD,
                    priority=priority.DATA_FWD,
                    flags=src_ofproto.OFPFF_SEND_FLOW_REM,
                    instructions=instructions_src))
            transaction.create(os.path.join(MAC_TO_FLOWS, dst_mac, src_dpid))
            LOGGER.info("Setup remote forward flow on (switch=%s) towards "
                        "(mac=%s)", src_dpid, dst_mac)

        # Setup a reverse flow on the dst switch
        if not self.zk.exists(os.path.join(MAC_TO_FLOWS, src_mac, dst_dpid)):
            actions_dst = [dst_ofproto_parser.OFPActionOutput(
                int(dst_fwd_port))]
            instructions_dst = [
                dst_datapath.ofproto_parser.OFPInstructionActions(
                    dst_ofproto.OFPIT_APPLY_ACTIONS,
                    actions_dst)]
            dst_datapath.send_msg(
                dst_ofproto_parser.OFPFlowMod(
                    datapath=dst_datapath,
                    match=dst_ofproto_parser.OFPMatch(
                        eth_dst=src_mac),
                    cookie=0,
                    command=dst_ofproto.OFPFC_ADD,
                    priority=priority.DATA_FWD,
                    flags=dst_ofproto.OFPFF_SEND_FLOW_REM,
                    instructions=instructions_dst))
            transaction.create(os.path.join(MAC_TO_FLOWS, src_mac, dst_dpid))
            LOGGER.info("Setup remote forward flow on (switch=%s) towards "
                        "(mac=%s)", dst_dpid, src_mac)
