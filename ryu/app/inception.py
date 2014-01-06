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
from ryu.app.inception_arp import InceptionArp
from ryu.app.inception_dhcp import InceptionDhcp
from ryu.app.inception_dhcp import DHCP_CLIENT_PORT
from ryu.app.inception_dhcp import DHCP_SERVER_PORT
import ryu.app.inception_priority as priority

LOGGER = logging.getLogger(__name__)

CONF = cfg.CONF
CONF.import_opt('zk_servers', 'ryu.app.inception_conf')
CONF.import_opt('zk_data', 'ryu.app.inception_conf')
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

    # Path in ZooKeeper, under which records the "IP address" of a VM
    # where a switch ("dpid") resides.
    #
    # {dpid => IP address}
    DPID_TO_IP = os.path.join(CONF.zk_data, 'dpid_to_ip')

    # Path in ZooKeeper, under which records the neighboring relations
    # of each switch.
    # "IP address": address of remote VMs.
    # "port": port number of dpid connecting IP address.
    #
    # {dpid => {IP address => port}}
    DPID_TO_CONNS = os.path.join(CONF.zk_data, 'dpid_to_conns')

    # Path in ZooKeeper, under which records the switch ("dpid") to
    # which a local "mac" connects, as well as the "port" of the
    # connection.
    #
    # {MAC => (dpid, port)}
    MAC_TO_DPID_PORT = os.path.join(CONF.zk_data, 'mac_to_dpid_port')

    # Path in ZooKeeper, under which record "dpid"s that has installed
    # a rule forwarding packets to "mac".
    #
    # {mac => {dpid => (True)}}
    MAC_TO_FLOWS = os.path.join(CONF.zk_data, 'mac_to_flows')

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
        self.zk.ensure_path(self.DPID_TO_IP)
        self.zk.ensure_path(self.DPID_TO_CONNS)
        self.zk.ensure_path(self.MAC_TO_DPID_PORT)
        self.zk.ensure_path(self.MAC_TO_FLOWS)

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
            socket = datapath.socket
            ip, port = socket.getpeername()
            host_ports = []
            all_ports = []

            # If the entry corresponding to the MAC already exists
            if dpid in self.zk.get_children(self.DPID_TO_IP):
                LOGGER.info("(switch=%s) already updated", dpid)
                return
            # Otherwise create an entry
            else:
                self.zk.create(os.path.join(self.DPID_TO_IP, dpid), ip)
                LOGGER.info("Add: (switch=%s) -> (ip=%s)", dpid, ip)

            # Collect port information.  Sift out ports connecting peer
            # switches and store them under DPID_TO_CONNS
            self.zk.ensure_path(os.path.join(self.DPID_TO_CONNS, dpid))
            for port in event.ports:
                # TODO(changbl): Use OVSDB. Parse the port name to get the IP
                # address of remote rVM to which the bridge builds a
                # VXLAN. E.g., obr1_184-53 => CONF.ip_prefix.184.53. Only
                # store the port connecting remote rVM.
                port_no = port.port_no
                all_ports.append(port_no)
                if port.name.startswith('obr') and '_' in port.name:
                    _, ip_suffix = port.name.split('_')
                    ip_suffix = ip_suffix.replace('-', '.')
                    peer_ip = '.'.join((CONF.ip_prefix, ip_suffix))
                    zk_path = os.path.join(self.DPID_TO_CONNS, dpid, peer_ip)
                    self.zk.create(zk_path, str(port_no))
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
                            in_port=port_no,
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
                ofproto_parser.OFPActionOutput(port=port_no)
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

        # A switch disconnects
        else:
            ip, _ = self.zk.get(os.path.join(self.DPID_TO_IP, dpid))

            # Delete switch's mapping from switch dpid to remote IP address
            self.zk.delete(os.path.join(self.DPID_TO_IP, dpid))
            LOGGER.info("Del: (switch=%s) -> (ip=%s)", dpid, ip)

            # Delete the switch's all connection info
            self.zk.delete(self.DPID_TO_CONNS, dpid, recursive=True)
            LOGGER.info("Del: (switch=%s) dpid_to_conns", dpid)

            # Delete all connected hosts
            for child in self.zk.get_children(self.MAC_TO_DPID_PORT):
                zk_path = os.path.join(self.MAC_TO_DPID_PORT, child)
                dpid_port, _ = self.zk.get(zk_path)
                if dpid_port.startswith(dpid):
                    self.zk.delete(zk_path)
            LOGGER.info("Del: (switch=%s) mac_to_dpid_port", dpid)

            # Delete all rules trackings
            for child in self.zk.get_children(self.MAC_TO_FLOWS):
                if dpid in self.zk.get_children(
                        os.path.join(self.MAC_TO_FLOWS, child)):
                    self.zk.delete(os.path.join(
                        self.MAC_TO_FLOWS, child, dpid))
            LOGGER.info("Del: (switch=%s) mac_to_flows", dpid)

    @handler.set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def packet_in_handler(self, event):
        """
        Handle when a packet is received
        """
        LOGGER.debug("Packet received")
        # do source learning
        self._do_source_learning(event)
        # handle ARP packet if it is
        self.inception_arp.handle(event)
        # handle DHCP packet if it is
        self.inception_dhcp.handle(event)

    def _do_source_learning(self, event):
        """
        Learn MAC => (switch dpid, switch port) mapping from a packet,
        update data in MAC_TO_DPID_PORT. Also set up flow table for
        forwarding broadcast message
        """
        msg = event.msg
        datapath = msg.datapath
        dpid = dpid_to_str(datapath.id)
        ofproto_parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']

        whole_packet = packet.Packet(msg.data)
        ethernet_header = whole_packet.get_protocol(ethernet.ethernet)
        ethernet_src = ethernet_header.src

        if ethernet_src not in self.zk.get_children(
                os.path.join(self.MAC_TO_DPID_PORT)):
            dpid_port = dpid + ',' + str(in_port)
            self.zk.create(os.path.join(self.MAC_TO_DPID_PORT, ethernet_src),
                           dpid_port)
            LOGGER.info("Learn: (mac=%s) => (switch=%s, port=%s)", ethernet_src,
                        dpid, in_port)
            # Set unicast flow to ethernet_src
            actions_unicast = [ofproto_parser.OFPActionOutput(in_port)]
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
            self.zk.create(os.path.join(self.MAC_TO_FLOWS, ethernet_src, dpid),
                           makepath=True)
            LOGGER.info("Setup local forward flow on (switch=%s) towards "
                        "(mac=%s)", dpid, ethernet_src)
        else:
            dpid_port_record, _ = self.zk.get(os.path.join(
                self.MAC_TO_DPID_PORT, ethernet_src))
            dpid_record, in_port_record = dpid_port_record.split(',')
            # The host's switch changes, e.g., due to a VM live migration
            if dpid_record != dpid:
                ip, _ = self.zk.get(os.path.join(self.DPID_TO_IP, dpid))
                dpid_port_new = dpid + ',' + str(in_port)
                self.zk.set(os.path.join(self.MAC_TO_DPID_PORT, ethernet_src),
                            dpid_port_new)
                LOGGER.info("Update: (mac=%s) => (switch=%s, port=%s)",
                            ethernet_src, dpid, in_port)

                # Add a flow on new datapath towards ethernet_src
                flow_command = None
                zk_path = os.path.join(self.MAC_TO_FLOWS, ethernet_src, dpid)
                if self.zk.exists(zk_path):
                    flow_command = ofproto.OFPFC_MODIFY_STRICT
                else:
                    flow_command = ofproto.OFPFC_ADD
                    self.zk.create(zk_path, makepath=True)
                actions_inport = [ofproto_parser.OFPActionOutput(in_port)]
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
                        os.path.join(self.MAC_TO_FLOWS, ethernet_src)):
                    if remote_dpid == dpid:
                        continue

                    remote_datapath = self.dpset.get(str_to_dpid(remote_dpid))
                    remote_fwd_port_str, _ = self.zk.get(os.path.join(
                        self.DPID_TO_CONNS, remote_dpid, ip))
                    remote_fwd_port = int(remote_fwd_port_str)
                    actions_remote = [
                        ofproto_parser.OFPActionOutput(
                            remote_fwd_port)]
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

    def setup_switch_fwd_flows(self, src_mac, dst_mac):
        """
        Given two MAC addresses, set up flows on their connected switches
        towards each other, so that the two can forward packets in between
        """
        src_dpid_port, _ = self.zk.get(os.path.join(
            self.MAC_TO_DPID_PORT, src_mac))
        src_dpid, src_port = src_dpid_port.split(',')
        dst_dpid_port, _ = self.zk.get(os.path.join(
            self.MAC_TO_DPID_PORT, dst_mac))
        dst_dpid, dst_port = dst_dpid_port.split(',')

        # If src_dpid == dst_dpid, no need to set up flows
        if src_dpid == dst_dpid:
            return

        src_ip, _ = self.zk.get(os.path.join(self.DPID_TO_IP, src_dpid))
        dst_ip, _ = self.zk.get(os.path.join(self.DPID_TO_IP, dst_dpid))
        src_fwd_port_str, _ = self.zk.get(os.path.join(
            self.DPID_TO_CONNS, src_dpid, dst_ip))
        src_fwd_port = int(src_fwd_port_str)
        dst_fwd_port_str, _ = self.zk.get(os.path.join(
            self.DPID_TO_CONNS, dst_dpid, src_ip))
        dst_fwd_port = int(dst_fwd_port_str)
        src_datapath = self.dpset.get(str_to_dpid(src_dpid))
        dst_datapath = self.dpset.get(str_to_dpid(dst_dpid))
        src_ofproto = src_datapath.ofproto
        dst_ofproto = dst_datapath.ofproto
        src_ofproto_parser = src_datapath.ofproto_parser
        dst_ofproto_parser = dst_datapath.ofproto_parser

        # Setup a flow on the src switch
        if not self.zk.exists(os.path.join(
                self.MAC_TO_FLOWS, dst_mac, src_dpid)):
            actions_fwd = [src_ofproto_parser.OFPActionOutput(src_fwd_port)]
            instructions_fwd = [
                src_datapath.ofproto_parser.OFPInstructionActions(
                    src_ofproto.OFPIT_APPLY_ACTIONS,
                    actions_fwd)]
            src_datapath.send_msg(
                src_ofproto_parser.OFPFlowMod(
                    datapath=src_datapath,
                    match=src_ofproto_parser.OFPMatch(
                        eth_dst=dst_mac),
                    cookie=0,
                    command=src_ofproto.OFPFC_ADD,
                    priority=priority.DATA_FWD,
                    flags=src_ofproto.OFPFF_SEND_FLOW_REM,
                    instructions=instructions_fwd))
            self.zk.create(os.path.join(self.MAC_TO_FLOWS, dst_mac, src_dpid),
                           makepath=True)
            LOGGER.info("Setup remote forward flow on (switch=%s) towards "
                        "(mac=%s)", src_dpid, dst_mac)

        # Setup a reverse flow on the dst switch
        if not self.zk.exists(os.path.join(
                self.MAC_TO_FLOWS, src_mac, dst_dpid)):
            actions_dst = [dst_ofproto_parser.OFPActionOutput(dst_fwd_port)]
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
            self.zk.create(os.path.join(self.MAC_TO_FLOWS, src_mac, dst_dpid),
                           makepath=True)
            LOGGER.info("Setup remote forward flow on (switch=%s) towards "
                        "(mac=%s)", dst_dpid, src_mac)
