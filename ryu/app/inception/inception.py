"""
Inception Cloud SDN controller
"""

import logging
#import array
#import netaddr

from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller import network
from ryu.controller import ofp_event
from ryu.controller import handler
#from ryu.controller import controller
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib import mac
from ryu.lib.dpid import dpid_to_str
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
#from ryu.lib.packet import arp
#from ryu.lib.packet import ipv4
#from ryu.lib.packet import icmp

from ryu.app.inception.inception_arp import InceptionArp
#from app.inception.inception_dhcp import InceptionDhcp
from ryu.app.inception import priority

LOGGER = logging.getLogger(__name__)


class Inception(app_manager.RyuApp):
    """
    Inception cloud SDN controller
    """
    _CONTEXTS = {
        'network': network.Network,
        'dpset': dpset.DPSet
    }
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    max_len = 65535

    def __init__(self, ip_prefix, *args, **kwargs):
        """
        :param ip_prefix: X1.X2 in network's IP address X1.X2.X3.X4
        """
        self.ip_prefix = ip_prefix
        super(Inception, self).__init__(*args, **kwargs)
        # dpset: management of all connected switches
        self.dpset = kwargs['dpset']
        # network: port information of switches
        self.network = kwargs['network']
        ## data stuctures
        # dpid -> IP address: records the mapping from switch dpid) to
        # IP address of the rVM where it resides. This table is to
        # facilitate the look-up of dpid_ip_to_port
        self.dpid_to_ip = {}
        # (dpid, IP address) -> port: records the neighboring
        # relationship between switches. It is mapping from data path
        # ID (dpid) of a switch and IP address of neighboring rVM to
        # port number. Its semantics is that each entry stands for
        # connection between switches via some specific port. VXLan,
        # however, only stores information of IP address of rVM in
        # which neighbor switches lies.  Rather than storing the
        # mapping from dpid to dpid directly, we store mapping from
        # dpid to IP address. With further look-up in dpid_to_ip, the
        # dpid to dpid mapping can be retrieved.
        self.dpid_ip_to_port = {}
        # MAC => (dpid, port): mapping from host MAC address to (switch
        # dpid, switch port) of end hosts
        self.mac_to_dpid_port = {}
        # Store port information of each switch
        self.dpid_to_ports = {}
        # Store pair (dpid, mac):
        # dpid installed a rule forwarding packets to mac
        self.unicast_rule_tracking = []
        ## modules
        # ARP
        self.inception_arp = InceptionArp(self)
        # DHCP
        # self.inception_dhcp = InceptionDhcp(self)

    @handler.set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def switch_connection_handler(self, event):
        """
        Handle when a switch event is received
        """
        datapath = event.dp
        dpid = datapath.id
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser

        # A new switch connects
        if event.enter is True:
            socket = datapath.socket
            ip, port = socket.getpeername()
            host_ports = []
            all_ports = []

            # Set the miss_send_len parameter of switch
#            datapath.send_msg(ofproto_parser.OFPSetConfig(
#                            datapath,
#                            ofproto.OFPC_FRAG_NORMAL,
#                            Inception.miss_send_len))

            # If the entry corresponding to the MAC already exists
            if dpid in self.dpid_to_ip:
                LOGGER.info("switch=%s already updated", dpid_to_str(dpid))
                return

            self.dpid_to_ip[dpid] = ip
            LOGGER.info("Add: switch=%s -> ip=%s", dpid_to_str(dpid), ip)

            # Collect port information.  Sift out ports connecting peer
            # switches and store them in dpid_ip_to_port
            for port in event.ports:
                # TODO(changbl): Parse the port name to get the IP
                # address of remote rVM to which the bridge builds a
                # VXLAN. E.g., obr1_184-53 => ip_prefix.184.53. Only
                # store the port connecting remote rVM.
                port_no = port.port_no
                all_ports.append(port_no)
                if port.name.startswith('obr') and '_' in port.name:
                    _, ip_suffix = port.name.split('_')
                    ip_suffix = ip_suffix.replace('-', '.')
                    peer_ip = '.'.join((self.ip_prefix, ip_suffix))
                    self.dpid_ip_to_port[(dpid, peer_ip)] = port_no
                    LOGGER.info("Add: (switch=%s, peer_ip=%s) -> port=%s",
                                dpid_to_str(dpid), peer_ip, port_no)
                elif port.name == 'eth_dhcp':
                    self.inception_dhcp.update_server(dpid, port_no)
                    LOGGER.info("DHCP server is found!")
                else:
                    # Store the port connecting local hosts
                    host_ports.append(port_no)

            # Store the mapping from switch dpid to ports
            self.dpid_to_ports[dpid] = all_ports

            # Intercepts all ARP packets and send them to the controller
            actions_arp = [ofproto_parser.OFPActionOutput(
                    ofproto.OFPP_CONTROLLER, Inception.max_len)]
            instruction_arp = [datapath.ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions_arp)]
            datapath.send_msg(ofproto_parser.OFPFlowMod(
                datapath=datapath,
                match=ofproto_parser.OFPMatch(
                    eth_type=ether.ETH_TYPE_ARP,
                ),
                priority=priority.ARP,
                flags=ofproto.OFPFF_SEND_FLOW_REM,
                cookie=0, command=ofproto.OFPFC_ADD,
                instructions=instruction_arp
            ))

            # Intercepts DHCP packets and send them to the controller
            instruction_dhcp = instruction_arp
            datapath.send_msg(ofproto_parser.OFPFlowMod(
                datapath=datapath,
                match=ofproto_parser.OFPMatch(
                    eth_type=ether.ETH_TYPE_IP,
                    ip_proto=inet.IPPROTO_UDP,
                    tcp_src=68,
                ),
                priority=priority.DHCP,
                flags=ofproto.OFPFF_SEND_FLOW_REM,
                cookie=0, command=ofproto.OFPFC_ADD,
                instructions=instruction_dhcp
            ))

            # Set up flow at the currently connected switch On
            # receiving a broadcast message, the switch forwards it to
            # all non-vxlan ports.
            # TODO(chenche): need to setup more flows for new hosts in the
            # future
            actions_bcast_in = [ofproto_parser.OFPActionOutput(
                port=port_no) for port_no in host_ports]
            instruction_bcast_in = [datapath.ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions_bcast_in)]
            datapath.send_msg(ofproto_parser.OFPFlowMod(
                datapath=datapath,
                match=ofproto_parser.OFPMatch(
                    eth_dst=mac.BROADCAST_STR,
                ),

                priority=priority.SWITCH_BCAST,
                flags=ofproto.OFPFF_SEND_FLOW_REM,
                cookie=0, command=ofproto.OFPFC_ADD,
                instructions=instruction_bcast_in
            ))

            # Default flows: Process via normal L2/L3 legacy switch
            # configuration
            actions_norm = [ofproto_parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            instruction_norm = [datapath.ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions_norm)]
            datapath.send_msg(ofproto_parser.OFPFlowMod(
                datapath=datapath,
                match=ofproto_parser.OFPMatch(),
                priority=priority.NORMAL,
                flags=ofproto.OFPFF_SEND_FLOW_REM,
                cookie=0, command=ofproto.OFPFC_ADD,
                instructions=instruction_norm
            ))
        # A switch disconnects
        else:
            LOGGER.info("Del: switch=%s -> ip=%s", dpid_to_str(dpid),
                        self.dpid_to_ip[dpid])
            # Delete switch's mapping from switch dpid to remote IP address
            del self.dpid_to_ip[dpid]

            # Delete all its port information
            del self.dpid_to_ports[dpid]
            for key in self.dpid_ip_to_port.keys():
                (_dpid, ip) = key
                if _dpid == dpid:
                    LOGGER.info("Del: (switch=%s, peer_ip=%s) -> port=%s",
                        dpid_to_str(_dpid), ip, self.dpid_ip_to_port[key])
                    del self.dpid_ip_to_port[key]

            # Delete all connected hosts
            for mac_addr in self.mac_to_dpid_port.keys():
                local_dpid, _ = self.mac_to_dpid_port[mac_addr]
                if local_dpid == dpid:
                    del self.mac_to_dpid_port[mac_addr]

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
        # self.inception_dhcp.handle(event)

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
        if ethernet_src not in self.mac_to_dpid_port:
            self.mac_to_dpid_port[ethernet_src] = (dpid, in_port)
            LOGGER.info("Add: (Mac %s) => (port %s)", ethernet_src, in_port)
            # Set unicast flow to ethernet_src
            actions_unicast = [ofproto_parser.OFPActionOutput(in_port)]
            instructions_unicast = [datapath.ofproto_parser.
                    OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                          actions_unicast)]
            datapath.send_msg(ofproto_parser.OFPFlowMod(
                    datapath=datapath,
                    match=ofproto_parser.OFPMatch(eth_dst=ethernet_src),
                    cookie=0, command=ofproto.OFPFC_ADD,
                    priority=priority.DATA_FWD,
                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                    instructions=instructions_unicast
                    ))
            self.unicast_rule_tracking.append((dpid, ethernet_src))
            # Set up broadcast flow when local hosts are sources
            # Note(changbl): where are "broadcast_ports"?
            actions_bcast_out = [ofproto_parser.OFPActionOutput(
                                                    ofproto.OFPP_ALL)]
            instructions_bcast_out = [datapath.ofproto_parser.
                    OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                          actions_bcast_out)]
            datapath.send_msg(ofproto_parser.OFPFlowMod(
                datapath=datapath,
                match=ofproto_parser.OFPMatch(
                    eth_src=ethernet_src,
                    eth_dst=mac.BROADCAST_STR,
                ),
                priority=priority.HOST_BCAST,
                flags=ofproto.OFPFF_SEND_FLOW_REM,
                cookie=0, command=ofproto.OFPFC_ADD,
                instructions=instructions_bcast_out
                ))
        else:
            (dpid_record, in_port_record) = self.mac_to_dpid_port[ethernet_src]
            if dpid_record != dpid:
                # The server has been migrated to other switches
                datapath_record = self.dpset.get(dpid_record)
                ip_datapath = self.dpid_to_ip[dpid]

                self.mac_to_dpid_port[ethernet_src] = (dpid, in_port)
                LOGGER.info("Update: (Mac %s) => (port %s)",
                                    ethernet_src, in_port)
                # Set up new broadcast flow
                actions_bcast_out = [ofproto_parser.OFPActionOutput(
                                                    ofproto.OFPP_ALL)]
                instructions_bcast_out = [datapath.ofproto_parser.
                    OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                          actions_bcast_out)]
                datapath.send_msg(ofproto_parser.OFPFlowMod(
                datapath=datapath,
                match=ofproto_parser.OFPMatch(
                    eth_src=ethernet_src,
                    eth_dst=mac.BROADCAST_STR,
                ),
                priority=priority.HOST_BCAST,
                flags=ofproto.OFPFF_SEND_FLOW_REM,
                cookie=0, command=ofproto.OFPFC_ADD,
                instructions=instructions_bcast_out))
                # Delete old broadcast flow
                datapath_record.send_msg(ofproto_parser.OFPFlowMod(
                    datapath=datapath_record,
                    match=ofproto_parser.OFPMatch(
                        eth_src=ethernet_src,
                        eth_dst=mac.BROADCAST_STR,
                        ),
                    priority=priority.HOST_BCAST,
                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                    cookie=0, command=ofproto.OFPFC_DELETE_STRICT,
                    instructions=instructions_bcast_out))
                # Add flow on new datapath towards ethernet_src
                flow_command = ofproto.OFPFC_ADD
                if (dpid, ethernet_src) in self.unicast_rule_tracking:
                    flow_command = ofproto.OFPFC_MODIFY_STRICT
                else:
                    self.unicast_rule_tracking.append((dpid, ethernet_src))
                actions_inport = [ofproto_parser.OFPActionOutput(in_port)]
                instructions_inport = [datapath.ofproto_parser.
                    OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                          actions_inport)]
                datapath.send_msg(ofproto_parser.OFPFlowMod(
                    datapath=datapath,
                    match=ofproto_parser.OFPMatch(eth_dst=ethernet_src),
                    cookie=0, command=flow_command,
                    priority=priority.DATA_FWD,
                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                    instructions=instructions_inport
                    ))
                # Mofidy flows on all other datapaths contacting ethernet_src
                actions_remote=[ofproto_parser.OFPActionOutput(
                                                        remote_fwd_port)]
                instructions_remote = [datapath.ofproto_parser.
                    OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                          actions_remote)]
                for (remote_dpid, dst_mac) in self.unicast_rule_tracking:
                    if remote_dpid == dpid or dst_mac != ethernet_src:
                        continue

                    remote_datapath = self.dpset.get(remote_dpid)
                    remote_fwd_port = self.dpid_ip_to_port[
                                            (remote_dpid, ip_datapath)]
                    remote_datapath.send_msg(ofproto_parser.OFPFlowMod(
                    datapath=remote_datapath,
                    match=ofproto_parser.OFPMatch(eth_dst=ethernet_src),
                    cookie=0, command=ofproto.OFPFC_MODIFY_STRICT,
                    priority=priority.DATA_FWD,
                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                    instructions=instructions_remote
                    ))

