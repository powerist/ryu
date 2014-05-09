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

from collections import defaultdict
import logging
import os
from SimpleXMLRPCServer import SimpleXMLRPCServer
import socket
from xmlrpclib import ServerProxy

from kazoo import client
from oslo.config import cfg

from ryu.app import inception_arp as i_arp
from ryu.app import inception_conf as i_conf
from ryu.app import inception_dhcp as i_dhcp
from ryu.app import inception_rpc as i_rpc
import ryu.app.inception_priority as i_priority
from ryu.app import inception_util as i_util
from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller import handler
from ryu.controller import ofp_event
from ryu.lib.dpid import dpid_to_str
from ryu.lib.dpid import str_to_dpid
from ryu.lib import mac
from ryu.lib import hub
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import dhcp
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet
from ryu import log
from ryu.ofproto import ether
from ryu.ofproto import inet

LOGGER = logging.getLogger(__name__)

CONF = cfg.CONF
CONF.import_opt('zk_servers', 'ryu.app.inception_conf')
CONF.import_opt('zk_data', 'ryu.app.inception_conf')
CONF.import_opt('zk_failover', 'ryu.app.inception_conf')
CONF.import_opt('zk_log_level', 'ryu.app.inception_conf')
CONF.import_opt('ip_prefix', 'ryu.app.inception_conf')
CONF.import_opt('dcenter', 'ryu.app.inception_conf')
CONF.import_opt('rpc_port', 'ryu.app.inception_conf')
CONF.import_opt('ofp_versions', 'ryu.app.inception_conf')
CONF.import_opt('peer_dcenters', 'ryu.app.inception_conf')
CONF.import_opt('remote_controller', 'ryu.app.inception_conf')
CONF.import_opt('num_switches', 'ryu.app.inception_conf')


class Inception(app_manager.RyuApp):
    """Inception Cloud SDN controller."""

    # Built-in Ryu modules, manage all connected switches: {dpid => datapath}
    _CONTEXTS = {
        'dpset': dpset.DPSet
    }
    # Default OpenFlow versions
    OFP_VERSIONS = CONF.ofp_versions

    def __init__(self, *args, **kwargs):
        super(Inception, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']

        # all network data (in the form of dict) is stored in ZooKeeper
        # TODO(chen): Add watcher to ZooKeeper for multi-active controllers
        # TODO(chen): Pull all data from zookeeper to local cache
        zk_logger = logging.getLogger('kazoo')
        zk_log_level = log.LOG_LEVELS[CONF.zk_log_level]
        zk_logger.setLevel(zk_log_level)
        zk_console_handler = logging.StreamHandler()
        zk_console_handler.setLevel(zk_log_level)
        zk_console_handler.setFormatter(CONF.log_formatter)
        zk_logger.addHandler(zk_console_handler)
        self.zk = client.KazooClient(hosts=CONF.zk_servers, logger=zk_logger)
        self.zk.start()

        # ensure all paths in ZooKeeper
        self.zk.ensure_path(CONF.zk_data)
        self.zk.ensure_path(CONF.zk_failover)
        # TODO(chen): Very strange to have a topology view with DPID and IP
        # mixed. Try to hide the IPs and only present connections between
        # DPIDs.
        self.zk.ensure_path(i_conf.MAC_TO_POSITION)
        self.zk.ensure_path(i_conf.IP_TO_MAC)
        self.zk.ensure_path(i_conf.DPID_TO_VMAC)
        # TODO(chen): gateways have to be stored pairwise
        # if each datacenter has more than one gateways

        # local in-memory caches of network data
        # TODO(chen): A better way to replace twin dictionaries?
        self.dpid_to_ip = {}
        self.ip_to_dpid = {}

        self.dpid_to_conns = defaultdict(dict)
        self.mac_to_position = {}
        # {vmac => {mac => time}}
        # Record guests which queried vmac
        # TODO(chen): Store data in Zookeeper
        self.vmac_to_queries = defaultdict(dict)
        self.ip_to_mac = {}
        self.mac_to_ip = {}

        self.gateway = None
        self.dcenter = CONF.dcenter
        # TODO(chen): Store the following two into zookeeper
        # Record switch id assignment
        self.switch_id_slots = [False] * (i_conf.SWITCH_MAXID + 1)
        # Record vm id assignment of each switch
        self.vm_id_slots = {}

        self.switch_count = 0
        self.switch_maxid = 0
        # {peer_dc => peer_gateway}: Record neighbor datacenter connection info
        peer_dcenters = CONF.peer_dcenters
        self.dcenter_to_info = i_util.parse_peer_dcenters(peer_dcenters)
        # Record the dpids on which to install flows to other datacenters
        # when gateway is connected
        self.gateway_waitinglist = []
        # Switch virtual MAC
        self.dpid_to_vmac = {}
        self.dcenter_to_rpc = {}
        self.dpid_to_topid = {}

        ## Inception relevent modules
        # ARP
        self.inception_arp = i_arp.InceptionArp(self)
        # DHCP
        self.inception_dhcp = i_dhcp.InceptionDhcp(self)
        # RPC
        self.inception_rpc = i_rpc.InceptionRpc(self)

        self.setup_rpc()
        self.initiate_cache()

    def setup_rpc(self):
        """Set up RPC server and RPC client to other controllers"""

        # RPC server
        host_addr = socket.gethostbyname(socket.gethostname())
        rpc_server = SimpleXMLRPCServer((host_addr, CONF.rpc_port),
                                        allow_none=True)
        rpc_server.register_introspection_functions()
        rpc_server.register_instance(self.inception_rpc)
        # server_thread = threading.Thread(target=rpc_server.serve_forever)
        hub.spawn(rpc_server.serve_forever)

        # Create RPC clients
        for dcenter in self.dcenter_to_info:
            controller_ip, _ = self.dcenter_to_info[dcenter]
            rpc_client = ServerProxy("http://%s:%s" %
                                          (controller_ip, CONF.rpc_port))
            self.dcenter_to_rpc[dcenter] = rpc_client

    def initiate_cache(self):
        """Pull network data from Zookeeper during controller boot up"""
        self.pull_data(i_conf.MAC_TO_POSITION, self.mac_to_position)
        self.pull_data(i_conf.IP_TO_MAC, self.ip_to_mac)
        self.pull_data(i_conf.DPID_TO_VMAC, self.dpid_to_vmac)

        # Copy data to twin data structure
        for (ip, mac) in self.ip_to_mac.items():
            self.mac_to_ip[mac] = ip

    def pull_data(self, zk_path, local_dic):
        """Copy all data under zk_path in Zookeeper into local cache"""
        for znode_unicode in self.zk.get_children(zk_path):
            znode = znode_unicode.encode('Latin-1')
            sub_path = os.path.join(zk_path, znode)
            zk_data, _ = self.zk.get(sub_path)
            if zk_path == i_conf.MAC_TO_POSITION:
                zk_data_dic = i_util.str_to_tuple(zk_data)
            else:
                zk_data_dic = zk_data
            local_dic[znode] = zk_data_dic

    @handler.set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def switch_connection_handler(self, event):
        """Handle when a switch event is received."""
        datapath = event.dp
        dpid = dpid_to_str(datapath.id)

        # A new switch connects
        if event.enter:
            self.switch_count += 1
            socket = datapath.socket
            ip, _ = socket.getpeername()

            if dpid not in self.vm_id_slots:
                self.vm_id_slots[dpid] = [False] * (i_conf.VM_MAXID + 1)

            switch_vmac = self.register_switch(dpid, ip)
            local_ports = self.parse_ports(dpid, ip, switch_vmac, event.ports)
            self.set_default_flows(datapath, local_ports)
            if dpid == self.gateway:
                self.handle_waitinglist(ip)
            self.set_dcenter_flows(dpid)
            self.do_failover()

        # A switch disconnects
        else:
            # TODO(chen): disconnection clean-up
            # Delete switch's mapping from switch dpid to remote IP address
            ip = self.dpid_to_ip[dpid]
            del self.ip_to_dpid[ip]
            del self.dpid_to_ip[dpid]
            LOGGER.info("Del: (switch=%s) -> (ip=%s)",
                        dpid, self.dpid_to_ip[dpid])

            # Delete the switch's all connection info
            del self.dpid_to_conns[dpid]
            LOGGER.info("Del: (switch=%s) dpid_to_conns", dpid)

            # Delete all connected guests
            for mac_addr in self.mac_to_position.keys():
                _, local_dpid, _, _ = self.mac_to_position[mac_addr]
                if local_dpid == dpid:
                    del self.mac_to_position[mac_addr]
                zk_path = os.path.join(i_conf.MAC_TO_POSITION, mac_addr)
                zk_data, _ = self.zk.get(zk_path)
                _, dpid_record, _ = i_util.str_to_tuple(zk_data)
                if dpid_record == dpid:
                    self.zk.delete(zk_path)
            LOGGER.info("Del: (switch=%s) mac_to_position", dpid)

    def register_switch(self, dpid, switch_ip):
        """Store necessary info of a newly connected switch"""
        # Update {dpid => switch_vmac}
        if dpid not in self.dpid_to_vmac:
            # New connection. Update both zookeeper and local cache
            dcenter_vmac = i_util.create_dc_vmac(int(self.dcenter))
            switch_vmac = i_util.create_swc_vmac(dcenter_vmac, dpid,
                                                 self.switch_id_slots)
            self.dpid_to_vmac[dpid] = switch_vmac
            zk_path_pfx = os.path.join(i_conf.DPID_TO_VMAC, dpid)
            self.zk.create(zk_path_pfx, switch_vmac)
        else:
            switch_vmac = self.dpid_to_vmac[dpid]

        # Update {dpid => ip}
        self.dpid_to_ip[dpid] = switch_ip
        self.ip_to_dpid[switch_ip] = dpid
        LOGGER.info("Add: (switch=%s) -> (ip=%s)", dpid, switch_ip)

        return switch_vmac

    def handle_waitinglist(self, gateway_ip):
        """Handle dpid_waitinglist: install dpid-to-remote-datacenter flow"""
        for dcenter in self.dcenter_to_info:
            peer_dc_vmac = i_util.create_dc_vmac(int(dcenter))
            for dpid_pending in self.gateway_waitinglist:
                gw_fwd_port = self.dpid_to_conns[dpid_pending][gateway_ip]
                self.set_nonlocal_flow(dpid_pending, peer_dc_vmac,
                                       i_conf.DCENTER_MASK,
                                       gw_fwd_port)

    def set_dcenter_flows(self, dpid):
        """Set up flows to other datacenters"""
        # Switchs connected after gateway: set up flows towards
        # remote datacenters through gateway
        if self.gateway is not None:
            if dpid != self.gateway:
                for dcenter in self.dcenter_to_info:
                    peer_dc_vmac = i_util.create_dc_vmac(int(dcenter))
                    gw_ip = self.dpid_to_ip[self.gateway]
                    gw_fwd_port = self.dpid_to_conns[dpid][gw_ip]
                    self.set_nonlocal_flow(dpid, peer_dc_vmac,
                                           i_conf.DCENTER_MASK,
                                           gw_fwd_port)
        else:
            # The gateway switch has not connected
            self.gateway_waitinglist.append(dpid)

    def parse_ports(self, dpid, switch_ip, switch_vmac, ports):
        """Collect port information.  Sift out ports connecting peer
        switches and set up necessary flows

        @return: list of ports connecting local guests
        """

        non_mesh_ports = []
        for port in ports:
            # TODO(changbl): Use OVSDB. Parse the port name to get
            # the IP address of remote host to which the bridge
            # builds a tunnel (GRE/VXLAN). E.g., obr1_184-53 =>
            # CONF.ip_prefix.184.53. Only store the port
            # connecting remote host.
            port_no = str(port.port_no)
            # TODO(chen): Define functions in inception_util
            # to hide name processing
            # TODO(chen): Port name should be used
            # as a well-defined index.

            # TODO(chen): Clean up logic here
            if port.name.startswith('obr') and '_' in port.name:
                _, ip_suffix = port.name.split('_')
                ip_suffix = ip_suffix.replace('-', '.')
                peer_ip = '.'.join((CONF.ip_prefix, ip_suffix))
                self.dpid_to_conns[dpid][peer_ip] = port_no
                LOGGER.info("Add: (switch=%s, peer_ip=%s) -> (port=%s)",
                            dpid, peer_ip, port_no)
                peer_dpid = self.ip_to_dpid.get(peer_ip)

                # Install switch-to-switch flow
                if peer_dpid is not None:
                    peer_vmac = self.dpid_to_vmac[peer_dpid]
                    peer_fwd_port = self.dpid_to_conns[peer_dpid][switch_ip]
                    swc_mask = i_conf.SWITCH_MASK

                    self.set_nonlocal_flow(dpid, peer_vmac, swc_mask, port_no)
                    self.set_nonlocal_flow(peer_dpid, switch_vmac, swc_mask,
                                           peer_fwd_port)

            elif port.name == 'eth_dhcpp':
                LOGGER.info("DHCP server is found!")
                self.inception_dhcp.update_server(dpid, port_no)

            elif port.name.startswith('gate'):
                if self.gateway is None:
                    self.gateway = dpid

                _, dcenter = i_util.str_to_tuple(port.name, '_')
                _, remote_gw_ip = self.dcenter_to_info[dcenter]
                self.dpid_to_conns[dpid][remote_gw_ip] = port_no
                LOGGER.info("Inter-datacenter connection:"
                            "(switch=%s, peer_ip=%s) -> (port=%s)",
                            dpid, remote_gw_ip, port_no)
                non_mesh_ports.append(port_no)

                # Install gateway-to-remote-gateway flow
                peer_dc_vmac = i_util.create_dc_vmac(int(dcenter))
                self.set_nonlocal_flow(dpid, peer_dc_vmac, i_conf.DCENTER_MASK,
                                       port_no)

            else:
                # Store the port connecting local guests
                non_mesh_ports.append(port_no)

        return non_mesh_ports

    def do_failover(self):
        """Do failover"""
        if self.switch_count == CONF.num_switches:
            # TODO(chen): Failover with rpc
            self._do_failover()

    def _do_failover(self):
        """Check if any work is left by previous controller.
        If so, continue the unfinished work.
        """
        failover_node = self.zk.get_children(CONF.zk_failover)
        for znode_unicode in failover_node:
            znode = znode_unicode.encode('Latin-1')
            log_path = os.path.join(CONF.zk_failover, znode)
            data, _ = self.zk.get(log_path)
            data_tuple = i_util.str_to_tuple(data)

            if znode == i_conf.SOURCE_LEARNING:
                self.learn_new_vm(*data_tuple)
                self.delete_failover_log(i_conf.SOURCE_LEARNING)

            if znode == i_conf.ARP_LEARNING:
                self.inception_arp.do_arp_learning(data_tuple)
                self.delete_failover_log(i_conf.ARP_LEARNING)

            if znode == i_conf.MIGRATION:
                self.handle_migration(*data_tuple)
                self.delete_failover_log(i_conf.MIGRATION)

            if znode == i_conf.RPC_GATEWAY_FLOW:
                self.inception_rpc.set_gateway_flow(*data_tuple)
                self.delete_failover_log(i_conf.RPC_GATEWAY_FLOW)

            if znode == i_conf.RPC_REDIRECT_FLOW:
                self.inception_rpc.redirect_local_flow(*data_tuple)
                self.delete_failover_log(i_conf.RPC_REDIRECT_FLOW)

    def set_default_flows(self, datapath, non_mesh_ports):
        """Set up default flows on a connected switch"""

        # Set up one flow for ARP messages.
        # Intercepts all ARP packets and send them to the controller
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser

        actions_arp = [ofproto_parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER,
            ofproto.OFPCML_NO_BUFFER)]
        instruction_arp = [datapath.ofproto_parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS,
            actions_arp)]
        match_arp = ofproto_parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP)
        self.set_flow(datapath=datapath,
                      match=match_arp,
                      priority=i_priority.ARP,
                      flags=ofproto.OFPFF_SEND_FLOW_REM,
                      command=ofproto.OFPFC_ADD,
                      instructions=instruction_arp)

        # Set up two flows for DHCP messages
        actions_dhcp = [ofproto_parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER,
            ofproto.OFPCML_NO_BUFFER)]
        instruction_dhcp = [datapath.ofproto_parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS,
            actions_dhcp)]
        match_client = ofproto_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                               ip_proto=inet.IPPROTO_UDP,
                                               udp_src=i_dhcp.CLIENT_PORT)
        match_server = ofproto_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                               ip_proto=inet.IPPROTO_UDP,
                                               udp_src=i_dhcp.SERVER_PORT)
        # (1) Intercept all DHCP request packets and send to the controller
        self.set_flow(datapath=datapath,
                      match=match_client,
                      priority=i_priority.DHCP,
                      flags=ofproto.OFPFF_SEND_FLOW_REM,
                      command=ofproto.OFPFC_ADD,
                      instructions=instruction_dhcp)
        # (2) Intercept all DHCP reply packets and send to the controller
        self.set_flow(datapath=datapath,
                      match=match_server,
                      priority=i_priority.DHCP,
                      flags=ofproto.OFPFF_SEND_FLOW_REM,
                      command=ofproto.OFPFC_ADD,
                      instructions=instruction_dhcp)

        # Set up two parts of flows for broadcast messages
        # (1) Broadcast messages from each non-mesh port: forward to all
        # (other) ports
        actions_bcast_out = [ofproto_parser.OFPActionOutput(ofproto.OFPP_ALL)]
        instructions_bcast_out = [
            datapath.ofproto_parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions_bcast_out)]
        for port_no in non_mesh_ports:
            match_out = ofproto_parser.OFPMatch(in_port=int(port_no),
                                                eth_dst=mac.BROADCAST_STR)
            self.set_flow(datapath=datapath,
                          match=match_out,
                          priority=i_priority.HOST_BCAST,
                          flags=ofproto.OFPFF_SEND_FLOW_REM,
                          command=ofproto.OFPFC_ADD,
                          instructions=instructions_bcast_out)
        # (2) Broadcast messages from each (tunnel) port: forward
        # to all local ports. Since i_priority.SWITCH_BCAST <
        # i_priority.HOST_BCAST, this guarantees that only
        # tunnel-port message will trigger this flow
        actions_bcast_in = [
            ofproto_parser.OFPActionOutput(port=int(port_no))
            for port_no in non_mesh_ports]
        instruction_bcast_in = [
            ofproto_parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions_bcast_in)]
        match_in = ofproto_parser.OFPMatch(eth_dst=mac.BROADCAST_STR)
        self.set_flow(datapath=datapath,
                      match=match_in,
                      priority=i_priority.SWITCH_BCAST,
                      flags=ofproto.OFPFF_SEND_FLOW_REM,
                      command=ofproto.OFPFC_ADD,
                      instructions=instruction_bcast_in)

        # To prevent loop, all non-matching packets are dropped
        instruction_norm = [
            datapath.ofproto_parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                [])]
        match_norm = ofproto_parser.OFPMatch()
        self.set_flow(datapath=datapath,
                      match=match_norm,
                      priority=i_priority.NORMAL,
                      flags=ofproto.OFPFF_SEND_FLOW_REM,
                      command=ofproto.OFPFC_ADD,
                      instructions=instruction_norm)

    @handler.set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def packet_in_handler(self, event):
        """Handle when a packet is received."""
        msg = event.msg
        datapath = msg.datapath
        dpid = dpid_to_str(datapath.id)
        in_port = str(msg.match['in_port'])

        # TODO(chen): Now we assume VMs are registered during DHCP and
        # gratuitous ARP during boot-up.
        self._process_packet_in(dpid, in_port, msg.data)

    def _process_packet_in(self, dpid, in_port, data):
        """Process raw data received from dpid through in_port."""
        whole_packet = packet.Packet(data)
        ethernet_header = whole_packet.get_protocol(ethernet.ethernet)
        ethernet_src = ethernet_header.src

        # do source learning
        self._do_source_learning(dpid, in_port, ethernet_src)
        # handle ARP packet if it is
        if ethernet_header.ethertype == ether.ETH_TYPE_ARP:
            arp_header = whole_packet.get_protocol(arp.arp)
            self.inception_arp.handle(dpid, in_port, arp_header)
        # handle DHCP packet if it is
        if ethernet_header.ethertype == ether.ETH_TYPE_IP:
            ip_header = whole_packet.get_protocol(ipv4.ipv4)
            if ip_header.proto == inet.IPPROTO_UDP:
                udp_header = whole_packet.get_protocol(udp.udp)
                if udp_header.src_port in (i_dhcp.CLIENT_PORT,
                                           i_dhcp.SERVER_PORT):
                    # Parsing DHCP packet
                    # TODO(chen): RYU does not parse DHCP now.
                    dhcp_binary = whole_packet.protocols[-1]
                    dhcp_header, _, _ = dhcp.dhcp.parser(dhcp_binary)
                    self.inception_dhcp.handle(dhcp_header, data)

    def _do_source_learning(self, dpid, in_port, ethernet_src):
        """Learn MAC => (switch dpid, switch port) mapping from a packet,
        update data in i_conf.MAC_TO_POSITION. Also set up flow table for
        forwarding broadcast message.
        """
        if ethernet_src not in self.mac_to_position:
            # New VM
            log_tuple = (dpid, in_port, ethernet_src)
            self.create_failover_log(i_conf.SOURCE_LEARNING, log_tuple)
            self.learn_new_vm(dpid, in_port, ethernet)
            self.delete_failover_log(i_conf.SOURCE_LEARNING)
        else:
            position = self.mac_to_position[ethernet_src]
            dcenter_old, dpid_old, port_old, vmac = position
            if (dpid_old, port_old) == (dpid, in_port):
                # No migration
                return False

            # The guest's switch changes, e.g., due to a VM migration
            log_tuple = (ethernet_src, dcenter_old, dpid_old, port_old, vmac,
                         dpid, in_port)
            self.create_failover_log(i_conf.MIGRATION, log_tuple)
            self.handle_migration(ethernet_src, dcenter_old, dpid_old,
                                  port_old, vmac, dpid, in_port)
            self.delete_failover_log(i_conf.MIGRATION)

    def learn_new_vm(self, dpid, port, mac):
        """Create vmac for new vm; Store vm position info;
        and install local forwarding flow"""
        if mac in self.mac_to_position:
            # vmac exists. Last controller crashes after creating vmac
            _, _, _, vmac = self.mac_to_position[mac]
        else:
            vm_id = i_util.generate_vm_id(mac, dpid, self.vm_id_slots)
            switch_vmac = self.dpid_to_vmac[dpid]
            vmac = i_util.create_vm_vmac(switch_vmac, vm_id)
            for rpc_client in self.dcenter_to_rpc.values():
                rpc_client.update_position(mac, self.dcenter, dpid,
                                           port, vmac)
            self.update_position(mac, self.dcenter, dpid, port, vmac)

        self.set_local_flow(dpid, vmac, mac, port)

    def create_failover_log(self, log_type, data_tuple):
        # Failover logging
        log_data = i_util.tuple_to_str(data_tuple)
        log_path = os.path.join(CONF.zk_failover, log_type)
        self.zk.create(log_path, log_data)

    def delete_failover_log(self, log_type):
        # Delete failover logging
        log_path = os.path.join(CONF.zk_failover, log_type)
        self.zk.delete(log_path)

    def set_flow(self, datapath, match, priority, flags, command,
                 instructions):
        """Send OFPFlowMod instruction to datapath"""

        parser = datapath.ofproto_parser
        datapath.send_msg(
            parser.OFPFlowMod(
                datapath=datapath,
                match=match,
                priority=priority,
                flags=flags,
                command=command,
                instructions=instructions))

    def update_position(self, mac, dcenter, dpid, port, vmac):
        """Update guest MAC and its connected switch"""
        data_tuple = (dcenter, dpid, port, vmac)
        if mac in self.mac_to_position:
            # Do not update duplicate information
            record = self.mac_to_position[mac]
            if record == data_tuple:
                return

        zk_data = i_util.tuple_to_str((dcenter, dpid, port, vmac))
        zk_path = os.path.join(i_conf.MAC_TO_POSITION, mac)
        if mac in self.mac_to_position:
            self.zk.set(zk_path, zk_data)
        else:
            self.zk.create(zk_path, zk_data)
        self.mac_to_position[mac] = (dcenter, dpid, port, vmac)
        LOGGER.info("Update: (mac=%s) => (dcenter=%s, switch=%s, port=%s,"
                    "vmac=%s)", mac, dcenter, dpid, port, vmac)

    def handle_migration(self, mac, dcenter_old, dpid_old, port_old, vmac_old,
                         dpid_new, port_new):
        """Set flows to handle VM migration properly"""
        LOGGER.info("Handle VM migration")

        if dcenter_old != self.dcenter:
            # Multi-datacenter migration
            # Install/Update a new flow at dpid_new towards mac.
            _, _, _, vmac_record = self.mac_to_position[mac]
            if vmac_record == vmac_old:
                # A new vmac has not been created
                switch_vmac = self.dpid_to_vmac[dpid_new]
                vm_id = i_util.generate_vm_id(mac, dpid_new, self.vm_id_slots)
                vmac_new = i_util.create_vm_vmac(switch_vmac, vm_id)
            else:
                # The previous controller crashes after creating vmac_new
                vmac_new = vmac_record

            # Store vmac_new
            self.update_position(mac, self.dcenter, dpid_new, port_new,
                                 vmac_new)
            for rpc_client in self.dcenter_to_rpc.values():
                rpc_client.update_position(mac, self.dcenter, dpid_new,
                                           port_new, vmac_new)
            # Instruct dpid_old in dcenter_old to redirect traffic
            rpc_client_old = self.dcenter_to_rpc[dcenter_old]
            rpc_client_old.redirect_local_flow(dpid_old, mac, vmac_old,
                                               vmac_new, self.dcenter)

            # Redirect gateway flows in peer datacenters towards vmac_old
            # and instruct other controllers to send gratuitous ARP
            # TODO(chen): When to delete it?
            for dcenter in self.dcenter_to_info:
                rpc_client = self.dcenter_to_rpc[dcenter]
                rpc_client.set_gateway_flow(mac, vmac_old, vmac_new,
                                            self.dcenter)

            # Set up flows at gateway to redirect flows bound for
            # old vmac in dcenter_old to new vmac
            ip_new = self.dpid_to_ip[dpid_new]
            gw_fwd_port = self.dpid_to_conns[self.gateway][ip_new]
            # TODO(chen): When to delete it?
            self.set_local_flow(self.gateway, vmac_old, vmac_new, gw_fwd_port)

            # Add flow at dpid_new towards vmac_new
            self.set_local_flow(dpid_new, vmac_new, mac, port_new)
            LOGGER.info("Add local forward flow on (switch=%s) towards "
                        "(mac=%s)", dpid_new, mac)

            # send gratuitous ARP to all local sending guests
            # TODO(chen): Only within ARP entry timeout
            for mac_query in self.vmac_to_queries[vmac_old]:
                ip = self.mac_to_ip[mac]
                ip_query = self.mac_to_ip[mac_query]
                self.inception_arp.send_arp_reply(ip, vmac_new, ip_query,
                                                  mac_query)
            del self.vmac_to_queries[vmac_old]
            return

        if dpid_old != dpid_new:
            # Same datacenter, different switch migration
            # Install/Update a new flow at dpid_new towards mac
            _, _, _, vmac_record = self.mac_to_position[mac]
            if vmac_record == vmac_old:
                switch_vmac = self.dpid_to_vmac[dpid_new]
                vm_id = i_util.generate_vm_id(mac, dpid_new, self.vm_id_slots)
                vmac_new = i_util.create_vm_vmac(switch_vmac, vm_id)
            else:
                # The previous controller crashes after creating vmac_new
                vmac_new = vmac_record

            # Store vmac_new
            self.update_position(mac, self.dcenter, dpid_new, port_new,
                                 vmac_new)
            for rpc_client in self.dcenter_to_rpc.values():
                rpc_client.update_position(mac, self.dcenter, dpid_new,
                                           port_new, vmac_new)
            # Instruct dpid_old to redirect traffic
            ip_new = self.dpid_to_ip[dpid_new]
            fwd_port = self.dpid_to_conns[dpid_old][ip_new]
            self.set_local_flow(dpid_old, vmac_old, vmac_new, fwd_port, False)
            LOGGER.info("Redirect forward flow on (switch=%s) towards "
                        "(mac=%s)", dpid_old, mac)
            # Add flow at dpid_new towards vmac_new
            self.set_local_flow(dpid_new, vmac_new, mac, port_new)
            LOGGER.info("Add local forward flow on (switch=%s) towards "
                        "(mac=%s)", dpid_new, mac)
            # send gratuitous ARP to all local sending guests
            # TODO(chen): Only within ARP entry timeout
            for mac_query in self.vmac_to_queries[vmac_old]:
                ip = self.mac_to_ip[mac]
                ip_query = self.mac_to_ip[mac_query]
                self.inception_arp.send_arp_reply(ip, vmac_new, ip_query,
                                                  mac_query)
            del self.vmac_to_queries[vmac_old]
            return

        if port_old != port_new:
            # Same switch, different port migration
            # Redirect traffic
            ip_new = self.dpid_to_ip[dpid_new]
            fwd_port = self.dpid_to_conns[dpid_old][ip_new]

            self.set_local_flow(dpid_old, vmac_old, mac, fwd_port, False)
            LOGGER.info("Update forward flow on (switch=%s) towards (mac=%s)",
                        dpid_old, mac)
            return

    def set_local_flow(self, dpid, vmac, mac, port, flow_add=True):
        """Set up a microflow on a switch (dpid) towards a guest (mac)
        The rule matches on dst vmac, rewrites it to mac and forwards to
        the appropriate port.
        mac can be another vmac.
        """
        datapath = self.dpset.get(str_to_dpid(dpid))
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser

        if flow_add:
            flow_cmd = ofproto.OFPFC_ADD
        else:
            flow_cmd = ofproto.OFPFC_MODIFY_STRICT

        actions = [ofproto_parser.OFPActionSetField(eth_dst=mac),
                   ofproto_parser.OFPActionOutput(int(port))]
        instructions = [
            datapath.ofproto_parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions)]
        match = ofproto_parser.OFPMatch(eth_dst=vmac)
        self.set_flow(datapath=datapath,
                      match=match,
                      priority=i_priority.DATA_FWD_LOCAL,
                      flags=ofproto.OFPFF_SEND_FLOW_REM,
                      command=flow_cmd,
                      instructions=instructions)

    def set_nonlocal_flow(self, dpid, mac, mask, port, flow_add=True):
        """Set up a microflow for unicast on switch DPID towards MAC

        @param flow_add: Boolean value.
            True: flow is added;
            False: flow is modified.
        """
        if mask == i_conf.DCENTER_MASK:
            mac_record = i_util.get_dc_prefix(mac)
            priority = i_priority.DATA_FWD_DCENTER
        else:
            mac_record = i_util.get_swc_prefix(mac)
            priority = i_priority.DATA_FWD_SWITCH

        datapath = self.dpset.get(str_to_dpid(dpid))
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser

        if flow_add:
            flow_cmd = ofproto.OFPFC_ADD
        else:
            flow_cmd = ofproto.OFPFC_MODIFY_STRICT

        actions = [ofproto_parser.OFPActionOutput(int(port))]
        instructions_src = [
            datapath.ofproto_parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions)]
        match_src = ofproto_parser.OFPMatch(eth_dst=(mac, mask))
        self.set_flow(datapath=datapath,
                      match=match_src,
                      priority=priority,
                      flags=ofproto.OFPFF_SEND_FLOW_REM,
                      command=flow_cmd,
                      instructions=instructions_src)

        LOGGER.info("Setup forward flow on (switch=%s) towards (mac=%s)",
                    dpid, mac_record)
