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

import logging
import os

from kazoo import client
from kazoo import exceptions as kazoo_exc
from oslo.config import cfg
import traceback

from ryu.app import inception_arp as i_arp
from ryu.app import inception_conf as i_conf
from ryu.app import inception_dhcp as i_dhcp
from ryu.app import inception_rpc as i_rpc
from ryu.app import inception_util as i_util
from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller import handler
from ryu.controller import ofp_event
from ryu.lib.dpid import dpid_to_str
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
CONF.import_opt('zookeeper_storage', 'ryu.app.inception_conf')
CONF.import_opt('zk_servers', 'ryu.app.inception_conf')
CONF.import_opt('zk_data', 'ryu.app.inception_conf')
CONF.import_opt('zk_failover', 'ryu.app.inception_conf')
CONF.import_opt('zk_log_level', 'ryu.app.inception_conf')
CONF.import_opt('ip_prefix', 'ryu.app.inception_conf')
CONF.import_opt('dhcp_port', 'ryu.app.inception_conf')
CONF.import_opt('self_dcenter', 'ryu.app.inception_conf')
CONF.import_opt('rpc_port', 'ryu.app.inception_conf')
CONF.import_opt('arp_timeout', 'ryu.app.inception_conf')
CONF.import_opt('ofp_versions', 'ryu.app.inception_conf')
CONF.import_opt('peer_dcenters', 'ryu.app.inception_conf')
CONF.import_opt('tenant_info', 'ryu.app.inception_conf')
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
        self.dcenter_id = CONF.self_dcenter

        self.vmac_manager = i_util.VmacManager(self.dcenter_id)
        self.topology = i_util.Topology()
        self.flow_manager = i_util.FlowManager(self.dpset, CONF.multi_tenancy)
        self.tenant_manager = i_util.TenantManager(CONF.tenant_info)
        self.arp_manager = i_util.ArpManager()
        self.switch_manager = i_util.SwitchManager(self.dcenter_id)
        self.vm_manager = i_util.VmManager()
        self.rpc_manager = i_util.RPCManager()

        self.switch_count = 0
        ## Inception relevent modules
        # ARP
        self.inception_arp = i_arp.InceptionArp(self)
        # DHCP
        self.inception_dhcp = i_dhcp.InceptionDhcp(self)
        # RPC
        self.inception_rpc = i_rpc.InceptionRpc(self)
        self.rpc_manager._setup_rpc_server_clients(self.inception_rpc)

        if CONF.zookeeper_storage:
            self._load_data()

    def _load_data(self):
        """Load network data from storage backend into controller """

        zk_logger = logging.getLogger('kazoo')
        zk_log_level = log.LOG_LEVELS[CONF.zk_log_level]
        zk_logger.setLevel(zk_log_level)
        zk_console_handler = logging.StreamHandler()
        zk_console_handler.setLevel(zk_log_level)
        zk_console_handler.setFormatter(logging.Formatter(CONF.log_formatter))
        zk_logger.addHandler(zk_console_handler)
        self.zk = client.KazooClient(hosts=CONF.zk_servers, logger=zk_logger)
        self.zk.start()

        self.zk.ensure_path(CONF.zk_data)
        self.zk.ensure_path(CONF.zk_failover)
        self.zk.ensure_path(i_conf.MAC_TO_POSITION)
        self.zk.ensure_path(i_conf.DPID_TO_VMAC)

        self._load_data_entry(i_conf.MAC_TO_POSITION, self.mac_to_position)
        # TODO(chen):
        #self._load_data_entry(i_conf.DPID_TO_VMAC, self.dpid_to_vmac)

    def _load_data_entry(self, zk_path, local_dic):
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
            LOGGER.info("New switch connects")
            self.switch_count += 1
            socket = datapath.socket
            ip, _ = socket.getpeername()

            # Update topology
            self.topology.update_switch(dpid, ip, event.ports)
            switch_id = self.switch_manager.add_local_switch(dpid)
            self.rpc_manager.rpc_update_swcid(self.dcenter_id, dpid, switch_id)
            self.vmac_manager.create_swc_vmac(self.dcenter_id, dpid, switch_id)
            if self.topology.is_gateway(dpid):
                self.flow_manager.set_new_gateway_flows(dpid, self.topology,
                                                        self.vmac_manager)
                self.flow_manager.handle_waitinglist(dpid, self.topology,
                                                     self.vmac_manager)
            else:
                self.flow_manager.set_new_switch_flows(dpid, self.topology,
                                                       self.vmac_manager)

            if self.topology.is_dhcp(dpid):
                self.inception_dhcp.update_server(self.topology.dhcp_switch,
                                                  self.topology.dhcp_port)

            # do failover if all switches are connected and have a data backend
            if (self.switch_count == CONF.num_switches and
                    CONF.zookeeper_storage):
                self._do_failover()

        # TODO(chen): A switch disconnects

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
                self.arp_manager.update_mapping(*data_tuple)
                self.rpc_manager.rpc_update_arp(*data_tuple)
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

        try:
            msg = event.msg
            datapath = msg.datapath
            dpid = dpid_to_str(datapath.id)
            in_port = str(msg.match['in_port'])

            # TODO(chen): Now we assume VMs are registered during DHCP and
            # gratuitous ARP during boot-up.
            self._process_packet_in(dpid, in_port, msg.data)
        except Exception:
            LOGGER.warning("Unexpected exception in packet handler %s",
                           traceback.format_exc())

    def _process_packet_in(self, dpid, in_port, data):
        """Process raw data received from dpid through in_port."""

        whole_packet = packet.Packet(data)
        ethernet_header = whole_packet.get_protocol(ethernet.ethernet)
        ethernet_src = ethernet_header.src

        try:
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
        except Exception:
            LOGGER.warning("Unexpected exception in packet processing: %s",
                           traceback.format_exc())

            LOGGER.warn("whole_packet=%s", whole_packet)
            LOGGER.warn("ethernet_header=%s", ethernet_header)
            LOGGER.warn("ethernet_src=%s", ethernet_src)

    def _do_source_learning(self, dpid, in_port, ethernet_src):
        """Learn MAC => (switch dpid, switch port) mapping from a packet,
        update data in i_conf.MAC_TO_POSITION. Also set up flow table for
        forwarding broadcast message.
        """
        if not self.vm_manager.mac_exists(ethernet_src):
            # New VM
            log_tuple = (dpid, in_port, ethernet_src)
            if CONF.zookeeper_storage:
                self.create_failover_log(i_conf.SOURCE_LEARNING, log_tuple)
            self.learn_new_vm(dpid, in_port, ethernet_src)
            if CONF.zookeeper_storage:
                self.delete_failover_log(i_conf.SOURCE_LEARNING)
            return

        if self.vm_manager.position_shifts(ethernet_src, self.dcenter_id, dpid,
                                           in_port):
            if CONF.zookeeper_storage:
                self.create_failover_log(i_conf.MIGRATION, dpid, in_port)
            self.handle_migration(ethernet_src, dpid, in_port)
            if CONF.zookeeper_storage:
                self.delete_failover_log(i_conf.MIGRATION)

    def learn_new_vm(self, dpid, port, mac):
        """Create vmac for new vm; Store vm position info;
        and install local forwarding flow"""
        self.vm_manager.update_position(mac, self.dcenter_id, dpid, port)
        self.rpc_manager.rpc_update_position(mac, self.dcenter_id, dpid, port)

        vm_id = self.vm_manager.generate_vm_id(mac, dpid, self.switch_manager)
        self.rpc_manager.rpc_update_vmid(mac, vm_id)

        vmac = self.vmac_manager.create_vm_vmac(mac, self.tenant_manager,
                                                self.vm_manager)

        self.flow_manager.set_tenant_filter(dpid, vmac, mac)
        self.flow_manager.set_local_flow(dpid, vmac, mac, port)

    def create_failover_log(self, log_type, data_tuple):
        """Failover logging"""

        log_data = i_util.tuple_to_str(data_tuple)
        log_path = os.path.join(CONF.zk_failover, log_type)
        self.zk.create(log_path, log_data)

    def delete_failover_log(self, log_type):
        """Delete failover logging"""

        log_path = os.path.join(CONF.zk_failover, log_type)
        self.zk.delete(log_path)

    def handle_migration(self, mac, dpid_new, port_new):
        """Set flows to handle VM migration properly"""

        LOGGER.info("Handle VM migration")
        (dcenter_old, dpid_old, port_old) = self.vm_manager.get_position(mac)
        vmac_old = self.vmac_manager.get_vm_vmac(mac)
        if dcenter_old != self.dcenter_id:
            # Multi-datacenter migration
            # Store vmac_new
            self.vm_manager.update_position(mac, self.dcenter_id, dpid_new,
                                            port_new)
            self.rpc_manager.rpc_update_position(mac, self.dcenter_id,
                                                 dpid_new, port_new)

            vmac_record = self.vmac_manager.get_vm_vmac(mac)
            if vmac_record == vmac_old:
                # A new vmac has not been created

                # Revoke old vm_id
                vm_id_old = self.vm_manager.get_vm_id(mac)
                self.vm_manager.revoke_vm_id(mac, vm_id_old)
                self.switch_manager.recollect_vm_id(vm_id_old, dpid_old)
                self.rpc_manager.rpc_revoke_vmid(mac, vm_id_old, dpid_old)
                # Generate new vm_id
                vm_id = self.vm_manager.generate_vm_id(mac, dpid_new,
                                                       self.switch_manager)
                self.rpc_manager.rpc_update_vmid(mac, vm_id)
                vmac_manager = self.vmac_manager
                vmac_new = vmac_manager.create_vm_vmac(mac,
                                                       self.tenant_manager,
                                                       self.vm_manager)
            else:
                # The previous controller crashes after creating vmac_new
                # TODO(chen): RPC here?
                vmac_new = vmac_record

            # Instruct dpid_old in dcenter_old to redirect traffic
            self.rpc_manager.rpc_redirect_flow(mac, dcenter_old, dpid_old,
                                               vmac_old, vmac_new)

            # Redirect gateway flows in peer datacenters towards vmac_old
            # and instruct peer controllers to send gratuitous ARP
            self.rpc_manager.rpc_gateway_redirect_flows(mac, vmac_old,
                                                        vmac_new,
                                                        self.dcenter_id)

            # Set up flows at gateway to redirect flows bound for
            # old vmac in dcenter_old to new vmac
            # The flow will expire after ARP cache expires
            self.flow_manager.set_gateway_bounce_flow(dpid_new, vmac_new,
                                                      vmac_old, self.topology)

            # Add flow at dpid_new towards vmac_new
            self.flow_manager.set_local_flow(dpid_new, vmac_new, mac, port_new)
            LOGGER.info("Add local forward flow on (switch=%s) towards "
                        "(mac=%s)", dpid_new, mac)

            # send gratuitous ARP to all local sending guests
            for mac_query in self.vmac_manager.get_query_macs(vmac_old):
                ip = self.arp_manager.get_ip(mac)
                ip_query = self.arp_manager.get_ip(mac_query)
                self.inception_arp.send_arp_reply(ip, vmac_new, ip_query,
                                                  mac_query)
            self.vmac_manager.del_vmac_query(vmac_old)
            return

        if dpid_old != dpid_new:
            # Same datacenter, different switch migration
            # Install/Update a new flow at dpid_new towards mac
            vmac_record = self.vmac_manager.get_vm_vmac(mac)
            if vmac_record == vmac_old:
                # Revoke old vm_id
                vm_id_old = self.vm_manager.get_vm_id(mac)
                self.vm_manager.revoke_vm_id(mac, vm_id_old)
                self.switch_manager.recollect_vm_id(vm_id_old, dpid_old)
                self.rpc_manager.rpc_revoke_vmid(mac, vm_id_old, dpid_old)
                # Generate new vm_id
                vm_id = self.vm_manager.generate_vm_id(mac, dpid_new,
                                                       self.switch_manager)
                self.rpc_manager.rpc_update_vmid(mac, vm_id)
                vmac_manager = self.vmac_manager
                vmac_new = vmac_manager.create_vm_vmac(mac,
                                                       self.tenant_manager,
                                                       self.vm_manager)
            else:
                # The previous controller crashes after creating vmac_new
                # TODO(chen): RPC call?
                vmac_new = vmac_record

            # Store vmac_new
            self.vm_manager.update_position(mac, self.dcenter_id, dpid_new,
                                            port_new)
            self.rpc_manager.rpc_update_position(mac, self.dcenter_id,
                                                 dpid_new, port_new)
            # Instruct dpid_old to redirect traffic
            fwd_port = self.topology.get_fwd_port(dpid_old, dpid_new)
            self.flow_manager.set_local_flow(dpid_old, vmac_old, vmac_new,
                                             fwd_port, False, CONF.arp_timeout)
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
            for mac_query in self.vmac_manager.get_query_macs(vmac_old):
                ip = self.arp_manager.get_ip(mac)
                ip_query = self.arp_manager.get_ip(mac_query)
                self.inception_arp.send_arp_reply(ip, vmac_new, ip_query,
                                                  mac_query)
            self.vmac_manager.del_vmac_query(vmac_old)
            return

        if port_old != port_new:
            # Same switch, different port migration
            # Redirect traffic
            self.flow_manager.set_local_flow(dpid_old, vmac_old, mac, port_new,
                                             False)
            LOGGER.info("Update forward flow on (switch=%s) towards (mac=%s)",
                        dpid_old, mac)
            return
