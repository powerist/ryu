"""
Inception Cloud SDN controller
"""

from collections import defaultdict
import logging

from oslo.config import cfg
from kazoo.client import KazooClient

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
CONF.register_opts([
    cfg.StrOpt('ip_prefix',
               default='192.168',
               help="X1.X2 in your network's IP address X1.X2.X3.X4"),
    cfg.StrOpt('zk_data_path',
               default='/data',
               help="Path for storing all mappings")])


class Inception(app_manager.RyuApp):
    """
    Inception Cloud SDN controller
    """
    _CONTEXTS = {
        'dpset': dpset.DPSet
    }
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    MAX_LEN = 65535

    def __init__(self, *args, **kwargs):
        super(Inception, self).__init__(*args, **kwargs)

        self.ip_prefix = CONF.ip_prefix

        self.zk_client = KazooClient(hosts=CONF.zk_servers)
        self.zk_client.start()

        self.zk_client.ensure_path(CONF.zk_data_path)

        # {dpid => datapath}:
        # dpset: management of all connected switches
        self.dpset = kwargs['dpset']

        # {dpid => IP address}:
        # Records the "IP address" of rVM where a switch ("dpid") resides.
        # self.dpid_to_ip = {}
        self.dpid_to_ip_zk = CONF.zk_data_path + '/dpid_to_ip'
        self.zk_client.ensure_path(self.dpid_to_ip_zk)

        # {dpid => {IP address => port}}:
        # Records the neighboring relations of each switch.
        # "IP address": address of remote VMs
        # "port": port number of dpid connecting IP address
        # self.dpid_to_conns = defaultdict(dict)
        self.dpid_to_conns_zk = CONF.zk_data_path + '/dpid_to_conns'
        self.zk_client.ensure_path(self.dpid_to_conns_zk)

        # {MAC => (dpid, port)}:
        # Records the switch ("dpid") to which a local "mac" connects,
        # as well as the "port" of the connection.
        # self.mac_to_dpid_port = {}
        self.mac_to_dpid_port_zk = CONF.zk_data_path + '/mac_to_dpid_port'
        self.zk_client.ensure_path(self.mac_to_dpid_port_zk)

        # {mac => {dpid => True}}::
        # Record "dpid"s that has installed a rule forwarding packets to "mac"
        # self.mac_to_flows = defaultdict(dict)
        self.mac_to_flows_zk = CONF.zk_data_path + '/mac_to_flows'
        self.zk_client.ensure_path(self.mac_to_flows_zk)

        ## Modules
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
        dpid = datapath.id
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser
        dpid_path = self.dpid_to_ip_zk + '/' + dpid_to_str(dpid)
        dpid_conns_path = self.dpid_to_conns_zk + '/' + dpid_to_str(dpid)

        # A new switch connects
        if event.enter is True:
            socket = datapath.socket
            ip, port = socket.getpeername()
            host_ports = []
            all_ports = []

            # If the entry corresponding to the MAC already exists
            dpid_list = self.zk_client.get_children(self.dpid_to_ip_zk)
            if dpid in dpid_list:
                LOGGER.info("(switch=%s) already updated", dpid_to_str(dpid))
                return

            if not self.zk_client.exists(dpid_path):
                self.zk_client.create(dpid_path, ip)
            LOGGER.info("Add: (switch=%s) -> (ip=%s)", dpid_to_str(dpid), ip)
            self.zk_client.ensure_path(dpid_conns_path)

            # Collect port information.  Sift out ports connecting peer
            # switches and store them in dpid_to_conns
            for port in event.ports:
                # TODO(changbl): Use OVSDB. Parse the port name to get the IP
                # address of remote rVM to which the bridge builds a
                # VXLAN. E.g., obr1_184-53 => ip_prefix.184.53. Only
                # store the port connecting remote rVM.
                port_no = port.port_no
                all_ports.append(port_no)
                if port.name.startswith('obr') and '_' in port.name:
                    _, ip_suffix = port.name.split('_')
                    ip_suffix = ip_suffix.replace('-', '.')
                    peer_ip = '.'.join((self.ip_prefix, ip_suffix))
                    ip_path = dpid_conns_path + '/' + peer_ip
                    self.zk_client.ensure_path(ip_path)
                    self.zk_client.set(ip_path, str(port_no))
                    LOGGER.info("Add: (switch=%s, peer_ip=%s) -> (port=%s)",
                                dpid_to_str(dpid), peer_ip, port_no)
                elif port.name == 'eth_dhcp':
                    self.inception_dhcp.update_server(dpid, port_no)
                    LOGGER.info("DHCP server is found!")
                else:
                    # Store the port connecting local hosts
                    host_ports.append(port_no)

            # Set up one flow for ARP messages
            # Intercepts all ARP packets and send them to the controller
            actions_arp = [
                ofproto_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                               Inception.MAX_LEN)
                ]
            instruction_arp = [
                datapath.ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    actions_arp
                    )
                ]
            datapath.send_msg(
                ofproto_parser.OFPFlowMod(
                    datapath=datapath,
                    match=ofproto_parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP),
                    priority=priority.ARP,
                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                    cookie=0,
                    command=ofproto.OFPFC_ADD,
                    instructions=instruction_arp
                    )
                )

            # Set up two flows for DHCP messages
            # (1) Intercept all DHCP request packets and send to the controller
            actions_dhcp = [
                ofproto_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                               Inception.MAX_LEN)
                ]
            instruction_dhcp = [
                datapath.ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    actions_dhcp
                    )
                ]
            datapath.send_msg(
                ofproto_parser.OFPFlowMod(
                    datapath=datapath,
                    match=ofproto_parser.OFPMatch(
                            eth_type=ether.ETH_TYPE_IP,
                            ip_proto=inet.IPPROTO_UDP,
                            udp_src=DHCP_CLIENT_PORT
                            ),
                    priority=priority.DHCP,
                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                    cookie=0,
                    command=ofproto.OFPFC_ADD,
                    instructions=instruction_dhcp
                    )
                )
            # (2) Intercept all DHCP reply packets and send to the controller
            actions_dhcp = [
                ofproto_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                               Inception.MAX_LEN)
                ]
            instruction_dhcp = [
                datapath.ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    actions_dhcp
                    )
                ]
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
                    instructions=instruction_dhcp
                    )
                )

            # Set up two parts of flows for broadcast messages
            # (1) Broadcast messages from each local port: forward to all
            # (other) ports
            for port_no in host_ports:
                actions_bcast_out = [
                    ofproto_parser.OFPActionOutput(ofproto.OFPP_ALL)
                    ]
                instructions_bcast_out = [
                    datapath.ofproto_parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS,
                        actions_bcast_out
                        )
                    ]
                datapath.send_msg(
                    ofproto_parser.OFPFlowMod(
                        datapath=datapath,
                        match=ofproto_parser.OFPMatch(
                                in_port=port_no,
                                eth_dst=mac.BROADCAST_STR
                                ),
                        priority=priority.HOST_BCAST,
                        flags=ofproto.OFPFF_SEND_FLOW_REM,
                        cookie=0,
                        command=ofproto.OFPFC_ADD,
                        instructions=instructions_bcast_out
                        )
                    )
            # (2) Broadcast messages from each (tunnel) port: forward to all
            # local ports. Since priority.SWITCH_BCAST < priority.HOST_BCAST,
            # this guarantees that only tunnel-port message will trigger this
            # flow
            actions_bcast_in = [
                ofproto_parser.OFPActionOutput(port=port_no)
                for port_no in host_ports
                ]
            instruction_bcast_in = [
                datapath.ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    actions_bcast_in
                    )
                ]
            datapath.send_msg(
                ofproto_parser.OFPFlowMod(
                    datapath=datapath,
                    match=ofproto_parser.OFPMatch(eth_dst=mac.BROADCAST_STR),
                    priority=priority.SWITCH_BCAST,
                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                    cookie=0,
                    command=ofproto.OFPFC_ADD,
                    instructions=instruction_bcast_in
                    )
                )

            # Finally, setup a default flow
            # Process via normal L2/L3 legacy switch configuration
            actions_norm = [
                ofproto_parser.OFPActionOutput(ofproto.OFPP_NORMAL)
                ]
            instruction_norm = [
                datapath.ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    actions_norm
                    )
                ]
            datapath.send_msg(
                ofproto_parser.OFPFlowMod(
                    datapath=datapath,
                    match=ofproto_parser.OFPMatch(),
                    priority=priority.NORMAL,
                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                    cookie=0,
                    command=ofproto.OFPFC_ADD,
                    instructions=instruction_norm)
                )

        # A switch disconnects
        else:
            ip, zk_node = self.zk_client.get(dpid_path)
            LOGGER.info("Del: (switch=%s) -> (ip=%s)", dpid_to_str(dpid), ip)
            # Delete switch's mapping from switch dpid to remote IP address
            self.zk_client.delete(dpid_path)

            # Delete the switch's connection info
            self.zk_client.delete(dpid_conns_path, recursive=True)

            # Delete all connected hosts
            mac_list = self.zk_client.get_children(self.mac_to_dpid_port_zk)
            for mac_addr in mac_list:
                mac_path = self.mac_to_dpid_port_zk + '/' + mac_addr
                dpid_data, dpid_znode = self.zk_client.get(mac_path)
                if dpid_data.startswith(dpid_to_str(dpid)):
                    self.zk_client.delete(mac_path)

            # Delete all rules tracking
            mac_flow_list = self.zk_client.get_children(self.mac_to_flows_zk)
            for mac_addr in mac_flow_list:
                mac_flow_path = self.mac_to_flows_zk + '/' + mac_addr
                dpid_flow_list = self.zk_client.get_children(mac_flow_path)
                if dpid_to_str(dpid) in dpid_flow_list:
                    dpid_flow_path = mac_flow_path + '/' + dpid_to_str(dpid)
                    self.zk_client.delete(dpid_flow_path)

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
        update self.mac_to_dpid_port table. Also set up flow table for
        forwarding broadcast message
        """
        msg = event.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto_parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']

        whole_packet = packet.Packet(msg.data)
        ethernet_header = whole_packet.get_protocol(ethernet.ethernet)
        ethernet_src = ethernet_header.src

        mac_path = self.mac_to_dpid_port_zk + '/' + ethernet_src
        mac_flow_path = self.mac_to_flows_zk + '/' + ethernet_src
        mac_dpid_path = mac_flow_path + '/' + dpid_to_str(dpid)

        if not self.zk_client.exists(mac_path):
            mac_data = dpid_to_str(dpid) + ',' + str(in_port)
            self.zk_client.create(mac_path, mac_data)
            LOGGER.info("Learn: (mac=%s) => (switch=%s, port=%s)", ethernet_src,
                        dpid_to_str(dpid), in_port)
            # Set unicast flow to ethernet_src
            actions_unicast = [ofproto_parser.OFPActionOutput(in_port)]
            instructions_unicast = [
                datapath.ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    actions_unicast
                    )
                ]
            datapath.send_msg(
                ofproto_parser.OFPFlowMod(
                    datapath=datapath,
                    match=ofproto_parser.OFPMatch(
                        eth_dst=ethernet_src
                        ),
                    cookie=0,
                    command=ofproto.OFPFC_ADD,
                    priority=priority.DATA_FWD,
                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                    instructions=instructions_unicast
                    )
                )
            self.zk_client.create(mac_dpid_path, makepath=True)
            LOGGER.info("Setup local forward flow on (switch=%s) towards "
                        "(mac=%s)", dpid_to_str(dpid), ethernet_src)
        else:
            mac_record_raw, record_znode = self.zk_client.get(mac_path)
            mac_record = mac_record_raw.split(',')
            dpid_record_str = mac_record[0]
            dpid_record = str_to_dpid(dpid_record_str)
            # The host's switch changes, e.g., due to a VM live migration
            if dpid_record != dpid:
                dpid_path = self.dpid_to_ip_zk + '/' + dpid_to_str(dpid)
                ip_datapath, zk_node = self.zk_client.get(dpid_path)
                mac_new_data = dpid_to_str(dpid) + ',' + str(in_port)
                self.zk_client.create(mac_path, mac_new_data)
                LOGGER.info("Update: (mac=%s) => (switch=%s, port=%s)",
                            ethernet_src, dpid_to_str(dpid), in_port)

                # Add a flow on new datapath towards ethernet_src
                flow_command = None
                if self.zk_client.exists(mac_dpid_path):
                    flow_command = ofproto.OFPFC_MODIFY_STRICT
                else:
                    flow_command = ofproto.OFPFC_ADD
                    self.zk_client.create(mac_dpid_path)
                actions_inport = [ofproto_parser.OFPActionOutput(in_port)]
                instructions_inport = [
                    datapath.ofproto_parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS,
                        actions_inport
                        )
                    ]
                datapath.send_msg(
                    ofproto_parser.OFPFlowMod(
                        datapath=datapath,
                        match=ofproto_parser.OFPMatch(
                            eth_dst=ethernet_src
                            ),
                        cookie=0,
                        command=flow_command,
                        priority=priority.DATA_FWD,
                        flags=ofproto.OFPFF_SEND_FLOW_REM,
                        instructions=instructions_inport
                        )
                    )
                operation = ('Setup' if flow_command == ofproto.OFPFC_ADD
                          else 'Update')
                LOGGER.info("%s local forward flow on (switch=%s) towards "
                            "(mac=%s)", operation, dpid_to_str(dpid),
                            ethernet_src)

                # Mofidy flows on all other datapaths contacting ethernet_src
                dpid_list = self.zk_client.get_children(mac_flow_path)
                for remote_dpid_str in dpid_list:
                    remote_dpid = str_to_dpid(remote_dpid_str)
                    if remote_dpid == dpid:
                        continue

                    remote_datapath = self.dpset.get(remote_dpid)
                    fwd_port_path = (
                        self.dpid_to_conns_zk + '/' +
                        dpid_to_str(remote_dpid) + '/' +
                        ip_datapath
                        )
                    remote_fwd_port_str, remote_znode = (
                        self.zk_client.get(fwd_port_path)
                        )
                    remote_fwd_port = int(remote_fwd_port_str)
                    actions_remote = [
                        ofproto_parser.OFPActionOutput(remote_fwd_port)
                        ]
                    instructions_remote = [
                        datapath.ofproto_parser.OFPInstructionActions(
                            ofproto.OFPIT_APPLY_ACTIONS,
                            actions_remote
                            )
                        ]
                    remote_datapath.send_msg(
                        ofproto_parser.OFPFlowMod(
                            datapath=remote_datapath,
                            match=ofproto_parser.OFPMatch(
                                    eth_dst=ethernet_src
                                    ),
                            cookie=0,
                            command=ofproto.OFPFC_MODIFY_STRICT,
                            priority=priority.DATA_FWD,
                            flags=ofproto.OFPFF_SEND_FLOW_REM,
                            instructions=instructions_remote
                            )
                        )
                    LOGGER.info("Update remote forward flow on (switch=%s) "
                                "towards (mac=%s)", dpid_to_str(remote_dpid),
                                ethernet_src)

    def setup_switch_fwd_flows(self, src_mac, dst_mac):
        """
        Given two MAC addresses, set up flows on their connected switches
        towards each other, so that the two can forward packets in between
        """
        src_mac_path = self.mac_to_dpid_port_zk + '/' + src_mac
        src_mac_data_raw, src_znode = self.zk_client.get(src_mac_path)
        src_mac_data = src_mac_data_raw.split(',')
        src_dpid_str = src_mac_data[0]
        src_dpid = str_to_dpid(src_dpid_str)
        dst_mac_path = self.mac_to_dpid_port_zk + '/' + dst_mac
        dst_mac_data_raw, dst_znode = self.zk_client.get(dst_mac_path)
        dst_mac_data = dst_mac_data_raw.split(',')
        dst_dpid_str = dst_mac_data[0]
        dst_dpid = str_to_dpid(dst_dpid_str)

        # If src_dpid == dst_dpid, no need to set up flows
        if src_dpid == dst_dpid:
            return

        src_dpid_path = self.dpid_to_ip_zk + '/' + dpid_to_str(src_dpid)
        src_ip, src_znode = self.zk_client.get(src_dpid_path)
        dst_dpid_path = self.dpid_to_ip_zk + '/' + dpid_to_str(dst_dpid)
        dst_ip, src_znode = self.zk_client.get(dst_dpid_path)
        src_fwd_port_path = (
            self.dpid_to_conns_zk + '/' +
            dpid_to_str(src_dpid) + '/' +
            dst_ip
            )
        src_fwd_port_str, src_fwd_znode = self.zk_client.get(src_fwd_port_path)
        src_fwd_port = int(src_fwd_port_str)
        dst_fwd_port_path = (
            self.dpid_to_conns_zk + '/' +
            dpid_to_str(dst_dpid) + '/' +
            src_ip
            )
        dst_fwd_port_str, dst_fwd_znode = self.zk_client.get(dst_fwd_port_path)
        dst_fwd_port = int(dst_fwd_port_str)
        src_datapath = self.dpset.get(src_dpid)
        dst_datapath = self.dpset.get(dst_dpid)
        src_ofproto = src_datapath.ofproto
        dst_ofproto = dst_datapath.ofproto
        src_ofproto_parser = src_datapath.ofproto_parser
        dst_ofproto_parser = dst_datapath.ofproto_parser

        # Setup a flow on the src switch
        dst_mac_dpid_path = (
            self.mac_to_flows_zk + '/' +
            dst_mac + '/' +
            dpid_to_str(src_dpid)
            )
        if not self.zk_client.exists(dst_mac_dpid_path):
            actions_fwd = [src_ofproto_parser.OFPActionOutput(src_fwd_port)]
            instructions_fwd = [
                src_datapath.ofproto_parser.OFPInstructionActions(
                    src_ofproto.OFPIT_APPLY_ACTIONS,
                    actions_fwd
                    )
            ]
            src_datapath.send_msg(
                src_ofproto_parser.OFPFlowMod(
                    datapath=src_datapath,
                    match=src_ofproto_parser.OFPMatch(eth_dst=dst_mac),
                    cookie=0,
                    command=src_ofproto.OFPFC_ADD,
                    priority=priority.DATA_FWD,
                    flags=src_ofproto.OFPFF_SEND_FLOW_REM,
                    instructions=instructions_fwd
                    )
                )
            self.zk_client.create(dst_mac_dpid_path, makepath=True)
            LOGGER.info("Setup remote forward flow on (switch=%s) towards "
                        "(mac=%s)", dpid_to_str(src_dpid), dst_mac)

        # Setup a reverse flow on the dst switch
        src_mac_dpid_path = (
            self.mac_to_flows_zk + '/' +
            src_mac + '/' +
            dpid_to_str(dst_dpid)
            )
        if not self.zk_client.exists(src_mac_dpid_path):
            actions_dst = [dst_ofproto_parser.OFPActionOutput(dst_fwd_port)]
            instructions_dst = [
                dst_datapath.ofproto_parser.OFPInstructionActions(
                    dst_ofproto.OFPIT_APPLY_ACTIONS,
                    actions_dst
                    )
                ]
            dst_datapath.send_msg(
                dst_ofproto_parser.OFPFlowMod(
                    datapath=dst_datapath,
                    match=dst_ofproto_parser.OFPMatch(eth_dst=src_mac),
                    cookie=0, command=dst_ofproto.OFPFC_ADD,
                    priority=priority.DATA_FWD,
                    flags=dst_ofproto.OFPFF_SEND_FLOW_REM,
                    instructions=instructions_dst
                    )
                )
            self.zk_client.create(src_mac_dpid_path, makepath=True)
            LOGGER.info("Setup remote forward flow on (switch=%s) towards "
                        "(mac=%s)", dpid_to_str(dst_dpid), src_mac)
