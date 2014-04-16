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
CONF.import_opt('neighbor_dcenter', 'ryu.app.inception_conf')
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

        # TODO(chen): We need a znode in the zookeeper to remind a newly
        # connected controller of whether it is the first leader or a succesor

        # all network data (in the form of dict) is stored in ZooKeeper
        # TODO(chen): Add watcher to ZooKeeper for multi-active controllers
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
        self.zk.ensure_path(i_conf.DPID_TO_ID)
        self.zk.ensure_path(i_conf.MAC_TO_FLOWS)
        self.zk.ensure_path(i_conf.IP_TO_MAC)
        self.zk.ensure_path(i_conf.DPID_TO_VMAC)
        # TODO(chen): gateways have to be stored pairwise

        # local in-memory caches of network data
        self.dpid_to_ip = {}
        self.ip_to_dpid = {}

        self.dpid_to_conns = defaultdict(dict)
        self.mac_to_position = {}
        self.dpid_to_id = defaultdict(dict)
        self.mac_to_flows = defaultdict(dict)
        self.ip_to_mac = {}
        # Record the dpids on which to install flows to other datacenters
        self.gateway_waitinglist = []
        # Switch virtual MAC
        self.dpid_to_vmac = {}
        # TODO(chen): Find a better way to store gateway info and dcenter
        self.gateway = None
        self.gateway_port = None

        self.dcenter = CONF.dcenter
        self.neighbor_dcenter = CONF.neighbor_dcenter
        self.remote_controller = CONF.remote_controller
        # TODO(chen): Need a way to read in datacenter information
        #self.dcenter_list = []
        self.switch_count = 0
        self.dpid_to_topid = {}

        ## Inception relevent modules
        # ARP
        self.inception_arp = i_arp.InceptionArp(self)
        # DHCP
        self.inception_dhcp = i_dhcp.InceptionDhcp(self)
        # RPC
        self.inception_rpc = i_rpc.InceptionRpc(self)

        # RPC server
        host_addr = socket.gethostbyname(socket.gethostname())
        rpc_server = SimpleXMLRPCServer((host_addr, CONF.rpc_port),
                                        allow_none=True)
        rpc_server.register_introspection_functions()
        rpc_server.register_instance(self.inception_rpc)
        # server_thread = threading.Thread(target=rpc_server.serve_forever)
        hub.spawn(rpc_server.serve_forever)

        # RPC client
        # TODO(chen): Multiple remote controllers
        self.rpc_client = ServerProxy("http://%s:%s" %
                                      (self.remote_controller, CONF.rpc_port))

    @handler.set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def switch_connection_handler(self, event):
        """Handle when a switch event is received."""
        datapath = event.dp
        dpid = dpid_to_str(datapath.id)
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser

        # A new switch connects
        if event.enter:
            self.switch_count += 1
            socket = datapath.socket
            ip, port = socket.getpeername()
            non_mesh_ports = []

            # Initiate id counter of locally connected VM
            if dpid not in self.dpid_to_id:
                zk_path_dp = os.path.join(i_conf.DPID_TO_ID, dpid)
                self.zk.ensure_path(zk_path_dp)
                self.dpid_to_topid[dpid] = 1

            # Update {dpid => switch_vmac}
            if dpid not in self.dpid_to_vmac:
                # New connection. Update both zookeeper and local cache
                dcenter_vmac = i_util.create_dc_vmac(int(self.dcenter))
                switch_vmac = i_util.create_swc_vmac(dcenter_vmac,
                                                     self.switch_count)
                self.dpid_to_vmac[dpid] = switch_vmac
                zk_path_pfx = os.path.join(i_conf.DPID_TO_VMAC, dpid)
                self.zk.create(zk_path_pfx, switch_vmac)
            else:
                switch_vmac = self.dpid_to_vmac[dpid]

            # Update {dpid => ip}
            self.dpid_to_ip[dpid] = ip
            self.ip_to_dpid[ip] = dpid
            LOGGER.info("Add: (switch=%s) -> (ip=%s)", dpid, ip)

            # Collect port information.  Sift out ports connecting peer
            # switches and store them
            for port in event.ports:
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
                        peer_fwd_port = self.dpid_to_conns[peer_dpid][ip]
                        swc_mask = i_conf.SWITCH_MASK
                        txn = self.zk.transaction()
                        self.set_nonlocal_flow(dpid, peer_vmac, swc_mask,
                                               port_no, txn)
                        self.set_nonlocal_flow(peer_dpid, switch_vmac,
                                               swc_mask, peer_fwd_port, txn)
                        txn.commit()

                elif port.name == 'eth_dhcpp':
                    LOGGER.info("DHCP server is found!")
                    self.inception_dhcp.update_server(dpid, port_no)

                elif port.name.startswith('gate'):
                    _, dcenter, ip_suffix = port.name.split('_')
                    # TODO(chen): remote ip_prefix is hardcoded.
                    if dcenter == '1':
                        ip_prefix = '135.207'
                    else:
                        ip_prefix = '135.197'
                    remote_ip = '.'.join((ip_prefix, ip_suffix))
                    peer_dc_vmac = i_util.create_dc_vmac(int(dcenter))
                    # TODO(chen): multiple gateways
                    self.gateway = dpid
                    self.gateway_port = port_no
                    self.dpid_to_conns[dpid][remote_ip] = port_no
                    LOGGER.info("Inter-datacenter connection:"
                                "(switch=%s, peer_ip=%s) -> (port=%s)",
                                dpid, peer_ip, port_no)
                    non_mesh_ports.append(port_no)

                    # Install datacenter-to-datacenter flow
                    dc_mask = i_conf.DCENTER_MASK
                    txn = self.zk.transaction()
                    self.set_nonlocal_flow(dpid, peer_dc_vmac, dc_mask,
                                           port_no, txn)
                    peer_dcenter = int(self.neighbor_dcenter)
                    peer_dc_vmac = i_util.create_dc_vmac(peer_dcenter)
                    dc_mask = i_conf.DCENTER_MASK
                    for dpid_pending in self.gateway_waitinglist:
                        if dpid_pending == self.gateway:
                            continue
                        gateway_fwd_port = self.dpid_to_conns[dpid_pending][ip]
                        self.set_nonlocal_flow(dpid_pending, peer_dc_vmac,
                                               dc_mask, gateway_fwd_port, txn)
                    txn.commit()

                else:
                    # Store the port connecting local guests
                    non_mesh_ports.append(port_no)

            # Set up one flow for ARP messages
            # Intercepts all ARP packets and send them to the controller
            actions_arp = [ofproto_parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER)]
            instruction_arp = [datapath.ofproto_parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions_arp)]
            match_arp = ofproto_parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP)
            self.set_flow(datapth=datapath,
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
            for port_no in non_mesh_ports:
                actions_bcast_out = [
                    ofproto_parser.OFPActionOutput(
                        ofproto.OFPP_ALL)]
                instructions_bcast_out = [
                    datapath.ofproto_parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS,
                        actions_bcast_out)]
                match_out = ofproto_parser.OFPMatch(in_port=int(port_no),
                                                    eth_dst=mac.BROADCAST_STR),
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
            self.set_flow(datapth=datapath,
                          match=match_norm,
                          priority=i_priority.NORMAL,
                          flags=ofproto.OFPFF_SEND_FLOW_REM,
                          command=ofproto.OFPFC_ADD,
                          instructions=instruction_norm)

            # TODO(chen): Better way to manage topology
            # Install datacenter-to-datacenter flow
            if self.gateway is not None:
                if dpid != self.gateway:
                    peer_dcenter = int(self.neighbor_dcenter)
                    peer_dcenter_vmac = i_util.create_dc_vmac(peer_dcenter)
                    dcenter_mask = i_conf.DCENTER_MASK
                    gateway_ip = self.dpid_to_ip[self.gateway]
                    gateway_fwd_port = self.dpid_to_conns[dpid][gateway_ip]
                    txn = self.zk.transaction()
                    self.set_nonlocal_flow(dpid, peer_dcenter_vmac,
                                           dcenter_mask, gateway_fwd_port,
                                           txn)
                    txn.commit()
            else:
                # The gateway switch has not connected
                self.gateway_waitinglist.append(dpid)

            if self.switch_count == CONF.num_switches:
                # Do failover
                # TODO(chen): Failover with rpc
                # TODO(chen): Allow multiple logs
                self._do_failover()

        # A switch disconnects
        else:
            txn = self.zk.transaction()

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
                _, local_dpid, _ = self.mac_to_position[mac_addr]
                if local_dpid == dpid:
                    del self.mac_to_position[mac_addr]
                zk_path = os.path.join(i_conf.MAC_TO_POSITION, mac_addr)
                zk_data, _ = self.zk.get(zk_path)
                _, dpid_record, _ = i_util.str_to_tuple(zk_data)
                if dpid_record == dpid:
                    txn.delete(zk_path)
            LOGGER.info("Del: (switch=%s) mac_to_position", dpid)

            txn.commit()

    def _do_failover(self):
        """Check if any work is left by previous controller.
        If so, continue the unfinished work.
        """
        # TODO(chen): Failover for multi-datacenter arp
        # TODO(chen): Pull all data from zookeeper to local cache
        failover_node = self.zk.get_children(CONF.zk_failover)
        for znode_unicode in failover_node:
            znode = znode_unicode.encode('Latin-1')
            log_path = os.path.join(CONF.zk_failover, znode)
            data, _ = self.zk.get(log_path)
            (dpid, in_port) = i_util.str_to_tuple(znode)
            txn = self.zk.transaction()
            self._process_packet_in(dpid, in_port, data, txn)
            txn.delete(log_path)
            txn.commit()

    @handler.set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def packet_in_handler(self, event):
        """Handle when a packet is received."""
        msg = event.msg
        datapath = msg.datapath
        dpid = dpid_to_str(datapath.id)
        in_port = str(msg.match['in_port'])

        # Failover logging
        znode_name = i_util.tuple_to_str((dpid, in_port))
        log_path = os.path.join(CONF.zk_failover, znode_name)
        # TODO: several log_path possible with multithread
        # TODO(chen): Uncomment the following line
        # self.zk.create(log_path, msg.data)

        txn = self.zk.transaction()
        self._process_packet_in(dpid, in_port, msg.data, txn)
        txn.delete(log_path)
        txn.commit()

    def _process_packet_in(self, dpid, in_port, data, txn):
        """Process raw data received from dpid through in_port."""
        whole_packet = packet.Packet(data)
        ethernet_header = whole_packet.get_protocol(ethernet.ethernet)
        ethernet_src = ethernet_header.src

        # do source learning
        self._do_source_learning(dpid, in_port, ethernet_src, txn)
        # handle ARP packet if it is
        if ethernet_header.ethertype == ether.ETH_TYPE_ARP:
            arp_header = whole_packet.get_protocol(arp.arp)
            self.inception_arp.handle(dpid, in_port, arp_header, txn)
        # handle DHCP packet if it is
        # ERROR: DHCP header unparsable in ryu.
        if ethernet_header.ethertype == ether.ETH_TYPE_IP:
            ip_header = whole_packet.get_protocol(ipv4.ipv4)
            if ip_header.proto == inet.IPPROTO_UDP:
                udp_header = whole_packet.get_protocol(udp.udp)
                if udp_header.src_port in (i_dhcp.CLIENT_PORT,
                                           i_dhcp.SERVER_PORT):
                    self.inception_dhcp.handle(udp_header, ethernet_header,
                                               data)

    def _do_source_learning(self, dpid, in_port, ethernet_src, txn):
        """Learn MAC => (switch dpid, switch port) mapping from a packet,
        update data in i_conf.MAC_TO_POSITION. Also set up flow table for
        forwarding broadcast message.
        """
        if ethernet_src not in self.mac_to_position:
            vm_id = i_util.generate_vm_id(self.dpid_to_topid[dpid])
            switch_vmac = self.dpid_to_vmac[dpid]
            vmac = i_util.create_vm_vmac(switch_vmac, vm_id)
            self.update_position(ethernet_src, self.dcenter, dpid, in_port,
                                 vmac, txn)
            self.rpc_client.update_position(ethernet_src, self.dcenter, dpid,
                                            in_port, vmac)
            self.set_local_flow(dpid, vmac, ethernet_src, in_port, txn)
        else:
            position = self.mac_to_position[ethernet_src]
            dcenter_old, dpid_old, port_old, vmac = position
            # The guest's switch changes, e.g., due to a VM migration
            # We assume the environment is safe and attack is out of question
            if (dpid_old, port_old) == (dpid, in_port):
                # No migration
                return False

            self.handle_migration(ethernet_src, dcenter_old, dpid_old,
                                  port_old, vmac, dpid, in_port, txn)

            if (dpid_old, port_old) == (self.gateway, self.gateway_port):
                # Migration involves another datacenter
                self.rpc_client.update_migration_flow(ethernet_src,
                                                      self.dcenter)
                # TODO(chen): For all other datacenters, update gateway
                self.rpc_client.update_gateway_flow(ethernet_src, self.dcenter)

    def set_flow(self, datapath, match, priority, flags, command,
                 instructions):
        # Send OFPFlowMod instruction to datapath
        parser = datapath.ofproto_parser

        datapath.send_msg(
            parser.OFPFlowMod(
                datapath=datapath,
                match=match,
                priority=priority,
                flags=flags,
                command=command,
                instructions=instructions))

    def update_position(self, mac, dcenter, dpid, port, vmac, txn):
        """Update guest MAC and its connected switch"""
        zk_data = i_util.tuple_to_str((dcenter, dpid, port, vmac))
        zk_path = os.path.join(i_conf.MAC_TO_POSITION, mac)
        if mac in self.mac_to_position:
            txn.set_data(zk_path, zk_data)
        else:
            txn.create(zk_path, zk_data)
        # TODO(chen): Update remote position info in remote datacenter
        self.mac_to_position[mac] = (dcenter, dpid, port, vmac)
        LOGGER.info("Update: (mac=%s) => (dcenter=%s, switch=%s, port=%s,"
                    "vmac=%s)", mac, dcenter, dpid, port, vmac)

    def handle_migration(self, mac, dcenter_old, dpid_old, port_old, vmac_old,
                         dpid_new, port_new, txn):
        """Set flows to handle VM migration properly"""
        LOGGER.info("Handle VM migration")

        if dcenter_old != self.dcenter:
            # Multi-datacenter migration
            # Install/Update a new flow at dpid_new towards mac.
            switch_vmac = self.dpid_to_vmac[dpid_new]
            # TODO(Chen): Increase top id
            vm_id = i_util.generate_vm_id(self.dpid_to_topid[dpid_new])
            vmac_new = i_util.create_vm_vmac(switch_vmac, vm_id)

            self.update_position(mac, self.dcenter, dpid_new, port_new,
                                 vmac_new, txn)
            self.rpc_client.update_position(mac, self.dcenter, dpid_new,
                                            port_new, vmac_new)
            self.set_local_flow(dpid_new, vmac_new, mac, port_new, txn)
            LOGGER.info("Add local forward flow on (switch=%s) towards "
                        "(mac=%s)", dpid_new, mac)

            # Instruct dpid_old in dcenter_old to redirect traffic
            self.rpc_client.redirect_flow(dpid_old, vmac_old, vmac_new,
                                          self.dcenter)

            # TODO(chen): send gratuitous ARP to all sending guests (optional)
            return

        if dpid_old != dpid_new:
            # Same datacenter, different switch migration
            # Install/Update a new flow at dpid_new towards mac.
            switch_vmac = self.dpid_to_vmac[dpid_new]
            vm_id = i_util.generate_vm_id(self.dpid_to_topid[dpid_new])
            vmac_new = i_util.create_vm_vmac(switch_vmac, vm_id)

            self.update_position(mac, self.dcenter, dpid_new, port_new,
                                 vmac_new, txn)
            self.rpc_client.update_position(mac, self.dcenter, dpid_new,
                                            port_new, vmac_new)
            self.set_local_flow(dpid_new, vmac_new, mac, port_new, txn)
            LOGGER.info("Add local forward flow on (switch=%s) towards "
                        "(mac=%s)", dpid_new, mac)

            # Instruct dpid_old to redirect traffic
            ip_new = self.dpid_to_ip[dpid_new]
            fwd_port = self.dpid_to_conns[dpid_old][ip_new]
            self.set_local_flow(dpid_old, vmac_old, vmac_new, fwd_port, txn,
                                False)

            # TODO(chen): send gratuitous ARP to all sending guests (optional)
            return

        if port_old != port_new:
            # Same switch, different port migration
            # Redirect traffic
            ip_new = self.dpid_to_ip[dpid_new]
            fwd_port = self.dpid_to_conns[dpid_old][ip_new]

            self.set_local_flow(dpid_old, vmac_old, vmac_new, fwd_port, txn,
                                False)
            LOGGER.info("Update forward flow on (switch=%s) towards (mac=%s)",
                        dpid_old, mac)

    def set_local_flow(self, dpid, vmac, mac, port, txn, flow_add=True):
        """Set up a microflow on a switch (dpid) towards a local host (mac)
        The rule matches on dst vmac, rewrites it to mac and forwards to
        the appropriate port.
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
        self.set_flow(datapth=datapath,
                      match=match,
                      priority=i_priority.DATA_FWD,
                      flags=ofproto.OFPFF_SEND_FLOW_REM,
                      command=flow_cmd,
                      instructions=instructions)

    def set_nonlocal_flow(self, dpid, mac, mask, port, txn, flow_add=True):
        """Set up a microflow for unicast on switch DPID towards MAC

        @param flow_add: Boolean value.
            True: flow is added;
            False: flow is modified.
        """
        if mask == i_conf.DCENTER_MASK:
            mac_record = i_util.get_dc_prefix(mac)
        else:
            mac_record = i_util.get_swc_prefix(mac)
        if dpid in self.mac_to_flows[mac_record]:
            # Don't set up redundant flows
            return

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
                      priority=i_priority.DATA_FWD,
                      flags=ofproto.OFPFF_SEND_FLOW_REM,
                      command=flow_cmd,
                      instructions=instructions_src)

        if mac_record not in self.mac_to_flows:
            txn.create(os.path.join(i_conf.MAC_TO_FLOWS, mac_record))
        self.mac_to_flows[mac_record][dpid] = True
        txn.create(os.path.join(i_conf.MAC_TO_FLOWS, mac_record, dpid))

        LOGGER.info("Setup forward flow on (switch=%s) towards (mac=%s)",
                    dpid, mac_record)
