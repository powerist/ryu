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
from ryu.app import inception_priority as i_priority
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
CONF.import_opt('dhcp_port', 'ryu.app.inception_conf')
CONF.import_opt('gateway_ip', 'ryu.app.inception_conf')
CONF.import_opt('dhcp_ip', 'ryu.app.inception_conf')
CONF.import_opt('self_dcenter', 'ryu.app.inception_conf')
CONF.import_opt('rpc_port', 'ryu.app.inception_conf')
CONF.import_opt('arp_timeout', 'ryu.app.inception_conf')
CONF.import_opt('ofp_versions', 'ryu.app.inception_conf')
CONF.import_opt('peer_dcenters', 'ryu.app.inception_conf')
CONF.import_opt('tenant_info', 'ryu.app.inception_conf')
CONF.import_opt('remote_controller', 'ryu.app.inception_conf')
CONF.import_opt('num_switches', 'ryu.app.inception_conf')
CONF.import_opt('forwarding_bcast', 'ryu.app.inception_conf')
CONF.import_opt('multi_tenancy', 'ryu.app.inception_conf')


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
        zk_console_handler.setFormatter(logging.Formatter(CONF.log_formatter))
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

        self.vmac_manager = i_util.VmacManager()
        self.topology = i_util.Topology()
        self.flow_manager = i_util.FlowManager(self.dpset,
                                               CONF.multi_tenancy)

        self.dpid_to_conns = defaultdict(dict)
        # TODO(chen): Seperate vmac from position info
        self.mac_to_position = {}
        # {vmac => {mac => time}}
        # Record guests which queried vmac
        # TODO(chen): Store data in Zookeeper
        self.vmac_to_queries = defaultdict(dict)
        self.ip_to_mac = {}
        self.mac_to_ip = {}

        self.dcenter_id = CONF.self_dcenter
        self.vmac_manager.update_dcenter(self.dcenter_id)
        # Record the tenant information
        self.mac_to_tenant = {}
        self.tenant_list = i_util.parse_tenants(CONF.tenant_info)
        # TODO(chen): Dynamically assign tenant to macs
        if self.tenant_list is not None:
            for tenant_id, mac_tuple in enumerate(self.tenant_list, 1):
                for mac in mac_tuple:
                    self.mac_to_tenant[mac] = tenant_id

        self.switch_count = 0
        self.switch_maxid = 0

        # Record the dpids on which to install flows to other datacenters
        # when gateway is connected
        self.gateway_waitinglist = []

        # {peer_dc => peer_gateway}: Record neighbor datacenter connection info
        self.dcenter_to_info = i_util.parse_peer_dcenters(CONF.peer_dcenters)
        for dcenter in self.dcenter_to_info:
            self.vmac_manager.update_dcenter(dcenter)

        ## Inception relevent modules
        # ARP
        self.inception_arp = i_arp.InceptionArp(self)
        # DHCP
        self.inception_dhcp = i_dhcp.InceptionDhcp(self)
        # RPC
        self.inception_rpc = i_rpc.InceptionRpc(self)

        # {peer_dc => rpc_client}: Record neighbor datacenter RPC clients info
        self._setup_rpc_server_clients()

        self._init_cache()

    def _setup_rpc_server_clients(self):
        """Set up RPC server and RPC client to other controllers"""

        self.dcenter_to_rpc = {}

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

    def _init_cache(self):
        """Pull network data from Zookeeper during controller boot up"""
        self._pull_data(i_conf.MAC_TO_POSITION, self.mac_to_position)
        self._pull_data(i_conf.IP_TO_MAC, self.ip_to_mac)
        # TODO(chen):
        #self._pull_data(i_conf.DPID_TO_VMAC, self.dpid_to_vmac)

        # Copy data to twin data structure
        for (ip, mac) in self.ip_to_mac.items():
            self.mac_to_ip[mac] = ip

    def _pull_data(self, zk_path, local_dic):
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

            # Update topology
            self.topology.update_switch(dpid, ip, event.ports)
            # Create new vmac for the new switch
            switch_vmac = self.vmac_manager.update_switch(self.dcenter_id,
                                                          dpid)
            zk_path_pfx = os.path.join(i_conf.DPID_TO_VMAC, dpid)
            self.zk.create(zk_path_pfx, switch_vmac)

            if self.topology.is_gateway(dpid):
                self.flow_manager.set_new_gateway_flows(dpid, self.topology,
                                                        self.vmac_manager)
                self.flow_manager.handle_waitinglist(dpid, self.topology,
                                                     self.vmac_manager)
            else:
                self.flow_manager.set_new_switch_flows(dpid, self.topology,
                                                       self.vmac_manager)

            self.do_failover()

        # TODO(chen): A switch disconnects

    def do_failover(self):
        """Do failover"""
        if self.switch_count == CONF.num_switches:
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
            self.learn_new_vm(dpid, in_port, ethernet_src)
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
            vm_id = self.vmac_manager.generate_vm_id(mac, dpid)
            switch_vmac = self.vmac_manager.dpid_to_vmac[dpid]
            # TODO(chen): Tenant info should be pre-installed
            if self.tenant_list is None:
                self.mac_to_tenant[mac] = 1
                tenant_id = 1
            else:
                tenant_id = self.mac_to_tenant[mac]
            vmac = self.vmac_manager.create_vm_vmac(switch_vmac, vm_id,
                                                    tenant_id)
            for rpc_client in self.dcenter_to_rpc.values():
                rpc_client.update_position(mac, self.dcenter_id, dpid,
                                           port, vmac)
            self.update_position(mac, self.dcenter_id, dpid, port, vmac)

        self.flow_manager.set_tenant_filter(dpid, vmac, mac)
        self.flow_manager.set_local_flow(dpid, vmac, mac, port)

    def create_failover_log(self, log_type, data_tuple):
        # Failover logging
        log_data = i_util.tuple_to_str(data_tuple)
        log_path = os.path.join(CONF.zk_failover, log_type)
        self.zk.create(log_path, log_data)

    def delete_failover_log(self, log_type):
        # Delete failover logging
        log_path = os.path.join(CONF.zk_failover, log_type)
        self.zk.delete(log_path)

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

        if dcenter_old != self.dcenter_id:
            # Multi-datacenter migration
            # Install/Update a new flow at dpid_new towards mac.
            _, _, _, vmac_record = self.mac_to_position[mac]
            if vmac_record == vmac_old:
                # A new vmac has not been created
                switch_vmac = self.vmac_manager.dpid_to_vmac[dpid_new]
                vm_id = self.vmac_manager.generate_vm_id(mac, dpid_new)
                tenant_id = self.mac_to_tenant[mac]
                vmac_new = self.vmac_manager.create_vm_vmac(switch_vmac, vm_id,
                                                            tenant_id)
            else:
                # The previous controller crashes after creating vmac_new
                vmac_new = vmac_record

            # Store vmac_new
            self.update_position(mac, self.dcenter_id, dpid_new, port_new,
                                 vmac_new)
            for rpc_client in self.dcenter_to_rpc.values():
                rpc_client.update_position(mac, self.dcenter_id, dpid_new,
                                           port_new, vmac_new)
            # Instruct dpid_old in dcenter_old to redirect traffic
            rpc_client_old = self.dcenter_to_rpc[dcenter_old]
            rpc_client_old.redirect_local_flow(dpid_old, mac, vmac_old,
                                               vmac_new, self.dcenter_id)
            rpc_client_old.del_tenant_filter(dpid_old, mac)

            # Redirect gateway flows in peer datacenters towards vmac_old
            # and instruct other controllers to send gratuitous ARP
            # TODO(chen): When to delete it?
            for dcenter in self.dcenter_to_info:
                rpc_client = self.dcenter_to_rpc[dcenter]
                rpc_client.set_gateway_flow(mac, vmac_old, vmac_new,
                                            self.dcenter_id)

            # Set up flows at gateway to redirect flows bound for
            # old vmac in dcenter_old to new vmac
            # The flow will expire after ARP cache expires
            ip_new = self.dpid_to_ip[dpid_new]
            gw_fwd_port = self.dpid_to_conns[self.gateway][ip_new]
            datapath_gw = self.dpset.get(str_to_dpid(self.gateway))
            ofproto = datapath_gw.ofproto
            ofproto_parser = datapath_gw.ofproto_parser
            actions = [ofproto_parser.OFPActionSetField(eth_dst=vmac_new),
                       ofproto_parser.OFPActionOutput(int(gw_fwd_port))]
            instructions = [
                datapath_gw.ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    actions)]
            match_gw = ofproto_parser.OFPMatch(eth_dst=vmac_old)
            self.set_flow(datapath=datapath_gw,
                          match=match_gw,
                          table_id=i_conf.PRIMARY_TABLE,
                          priority=i_priority.DATA_FWD_LOCAL,
                          flags=ofproto.OFPFF_SEND_FLOW_REM,
                          hard_timeout=CONF.arp_timeout,
                          command=ofproto.OFPFC_ADD,
                          instructions=instructions)

            # Add flow at dpid_new towards vmac_new
            self.flow_manager.set_local_flow(dpid_new, vmac_new, mac, port_new)
            # Add tenant flow of mac at dpid_new
            self.flow_manager.set_tenant_filter(dpid_new, vmac_new, mac)

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
                switch_vmac = self.vmac_manager.dpid_to_vmac[dpid_new]
                vm_id = self.vmac_manager.generate_vm_id(mac, dpid_new)
                tenant_id = self.mac_to_tenant[mac]
                vmac_new = self.vmac_manager.create_vm_vmac(switch_vmac, vm_id,
                                                            tenant_id)
            else:
                # The previous controller crashes after creating vmac_new
                vmac_new = vmac_record

            # Store vmac_new
            self.update_position(mac, self.dcenter_id, dpid_new, port_new,
                                 vmac_new)
            for rpc_client in self.dcenter_to_rpc.values():
                rpc_client.update_position(mac, self.dcenter_id, dpid_new,
                                           port_new, vmac_new)
            # Instruct dpid_old to redirect traffic
            ip_new = self.dpid_to_ip[dpid_new]
            fwd_port = self.dpid_to_conns[dpid_old][ip_new]
            self.flow_manager.set_local_flow(dpid_old, vmac_old, vmac_new,
                                             fwd_port, False)
            LOGGER.info("Redirect forward flow on (switch=%s) towards "
                        "(mac=%s)", dpid_old, mac)
            # Add flow at dpid_new towards vmac_new
            self.flow_manager.set_local_flow(dpid_new, vmac_new, mac, port_new)
            # Add tenant flow of mac at dpid_new
            self.flow_manager.set_tenant_filter(dpid_new, vmac_new, mac)
            # Delete tenant flow of mac at dpid_old
            self.flow_manager.del_tenant_filter(dpid_old, mac)

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

            self.flow_manager.set_local_flow(dpid_old, vmac_old, mac, fwd_port,
                                             False)
            LOGGER.info("Update forward flow on (switch=%s) towards (mac=%s)",
                        dpid_old, mac)
            return
