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

from oslo.config import cfg
import traceback

from ryu.app import inception_arp as i_arp
from ryu.app import inception_dhcp as i_dhcp
from ryu.app import inception_rpc as i_rpc
from ryu.app import inception_util as i_util
from ryu.app.inception_util import Topology
from ryu.app.inception_util import InceptionPacket
from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller import handler
from ryu.controller import ofp_event
from ryu.lib.dpid import dpid_to_str
from ryu.lib.packet.arp import arp
from ryu.lib.packet.dhcp import dhcp
from ryu.lib.packet.ethernet import ethernet

LOGGER = logging.getLogger(__name__)

CONF = cfg.CONF
CONF.import_opt('zookeeper_storage', 'ryu.app.inception_conf')
CONF.import_opt('zk_servers', 'ryu.app.inception_conf')
CONF.import_opt('zk_log_level', 'ryu.app.inception_conf')
CONF.import_opt('ip_prefix', 'ryu.app.inception_conf')
CONF.import_opt('gateway_ips', 'ryu.app.inception_conf')
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
        self.topology = Topology.topology_from_gateways(CONF.gateway_ips)
        self.flow_manager = i_util.FlowManager(self.dpset, CONF.multi_tenancy)
        self.tenant_manager = i_util.TenantManager(CONF.tenant_info)
        self.arp_manager = i_util.ArpManager()
        self.switch_manager = i_util.SwitchManager(self.dcenter_id)
        self.vm_manager = i_util.VmManager()
        self.queue_manager = i_util.QueueManager()
        self.rpc_manager = i_util.RPCManager(self.dcenter_id)
        self.zk_manager = i_util.ZkManager(CONF.zookeeper_storage)
        dcenters = self.rpc_manager.get_dcenters()
        self.zk_manager.init_dcenter(dcenters)
        self.zk_manager.load_data(arp_manager=self.arp_manager,
                                  switch_manager=self.switch_manager,
                                  vm_manager=self.vm_manager,
                                  vmac_manager=self.vmac_manager,
                                  tenant_manager=self.tenant_manager)
        # Flag indicating if self is master controller
        self.master_ctl = True
        self.packet_queue = []
        self.switch_count = 0
        ## Inception relevent modules
        # ARP
        self.inception_arp = i_arp.InceptionArp(self)
        # DHCP
        self.inception_dhcp = i_dhcp.InceptionDhcp(self)
        # RPC
        self.inception_rpc = i_rpc.InceptionRpc(self)
        self.rpc_manager._setup_rpc_server_clients(self.inception_rpc)

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

            self.topology.update_switch(dpid, ip, event.ports)
            self.switch_manager.init_swc_vmids(dpid)
            switch_id = self.switch_manager.get_swc_id(self.dcenter_id, dpid)
            if switch_id is None:
                switch_id = self.switch_manager.generate_swc_id(dpid)
                self.rpc_manager.rpc_update_swcid(self.dcenter_id, dpid,
                                                  switch_id)
                self.vmac_manager.create_swc_vmac(self.dcenter_id, dpid,
                                                  switch_id)
                self.zk_manager.log_dpid_id(self.dcenter_id, dpid, switch_id)

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

            # do failover if all switches are connected
            if (self.switch_count == CONF.num_switches and
                    CONF.zookeeper_storage):
                self._do_failover()

        # TODO(chen): A switch disconnects

    def _do_failover(self):
        """Check if any work is left by previous controller.
        If so, continue the unfinished work.
        """
        (pktin_logs, rpc_logs) = self.zk_manager.get_failover_logs()
        # Do unfinished packt_in handling
        for pktin_log, raw_data in pktin_logs.items():
            dpid, in_port_str = i_util.str_to_tuple(pktin_log)
            in_port = int(in_port_str)
            pkt_data = bytearray(raw_data, 'Latin-1')
            packet = InceptionPacket(pkt_data)
            self._process_packet_in(dpid, in_port, packet)
            # Enqueue the log so that other controllers
            # can dump the corresponding packet
            self.queue_manager.enqueue(pkt_data)
            # Delete log after task is finished
            self.zk_manager.del_packetin_log(pktin_log)

        # Do unfinished rpc
        # TODO(chen): How to log rpc effectively?
        for rpc_log, rpc_data in rpc_logs.items():
            rpc_tuple = i_util.str_to_tuple(rpc_data)
            try:
                rpc_method = getattr(self.inception_rpc, rpc_log)
                rpc_method(*rpc_tuple)
            except AttributeError:
                LOGGER.warning("Unexpected exception in finding rpc method")

    @handler.set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def packet_in_handler(self, event):
        """Handle when a packet is received."""
        msg = event.msg
        datapath = msg.datapath
        dpid = dpid_to_str(datapath.id)
        in_port = str(msg.match['in_port'])
        packet = InceptionPacket(msg.data)

        if self.master_ctl:
            try:
                # Logging in zookeeper
                packet.serialize()
                packet_data = packet.data.decode('Latin-1').encode('Latin-1')
                pktin_log = i_util.tuple_to_str((dpid, str(in_port)))
                self.zk_manager.add_packetin_log(pktin_log, packet_data)

                self._process_packet_in(dpid, in_port, packet)

                # Enqueue the log so that other controllers
                # can dump the corresponding packet
                self.queue_manager.enqueue(packet_data)
                # Delete log after task is finished
                self.zk_manager.del_packetin_log(pktin_log)
            except Exception:
                LOGGER.warning("Unexpected exception in packet handler %s",
                               traceback.format_exc())
        else:
            # TODO(chen): slave controller consumes handled packets
            packet.serialize()
            packet_data = packet.data
            log_data = i_util.tuple_to_str((dpid, str(in_port), packet_data))
            self.packet_queue.append(log_data)

    def _process_packet_in(self, dpid, in_port, packet):
        """Process raw data received from dpid through in_port."""
        # Process packet
        try:
            ether_header = packet.get_protocol(ethernet)
            # do source learning
            ether_src = ether_header.src
            pos_old = self.vm_manager.get_position(ether_src)
            if pos_old:
                if (self.dcenter_id, dpid, in_port) != pos_old:
                    dcenter_old, dpid_old, port_old = pos_old
                    self.handle_migration(ether_src, dcenter_old, dpid_old,
                                          port_old, dpid, in_port)
            else:
                self.learn_new_vm(dpid, in_port, ether_src)
            # Handle ARP packet
            arp_header = packet.get_protocol(arp)
            if arp_header:
                self.inception_arp.handle(dpid, in_port, arp_header)
            # handle DHCP packet if it is
            dhcp_header = packet.get_protocol(dhcp)
            if dhcp_header:
                self.inception_dhcp.handle(dhcp_header, packet.raw_data)

        except Exception:
            LOGGER.warning("Unexpected exception in packet processing: %s",
                           traceback.format_exc())

            LOGGER.warn("packet=%s", packet)
            LOGGER.warn("ether_header=%s", ether_header)
            LOGGER.warn("ether_src=%s", ether_src)

    def learn_new_vm(self, dpid, port, mac):
        """Create vmac for new vm; Store vm position info;
        and install local forwarding flow"""
        # Update position
        LOGGER.info("Update vm position: (mac=%s) => (datacenter=%s, "
                    "switch=%s, port=%s)",
                    mac, self.dcenter_id, dpid, port)
        pos = self.vm_manager.get_position(mac)
        if pos is None:
            self.vm_manager.update_position(mac, self.dcenter_id, dpid, port)
            self.rpc_manager.rpc_update_position(mac, self.dcenter_id, dpid,
                                                 port)
        # Create vm_id
        vm_id = self.vm_manager.get_vm_id(mac)
        if vm_id is None:
            vm_id = self.vm_manager.generate_vm_id(mac, dpid,
                                                   self.switch_manager)
            self.rpc_manager.update_vmid(mac, dpid, vm_id)
            vmac = self.vmac_manager.create_vm_vmac(mac, self.tenant_manager,
                                                    self.vm_manager)
        # Set up local flow
        self.flow_manager.set_tenant_filter(dpid, vmac, mac)
        self.flow_manager.set_local_flow(dpid, vmac, mac, port)
        # Register position and vm_id
        self.zk_manager.log_vm(self.dcenter_id, dpid, port, mac, vm_id)

    def handle_migration(self, mac, dcenter_old, dpid_old, port_old, dpid_new,
                         port_new):
        """Set flows to handle VM migration properly"""
        LOGGER.info("Handle VM migration")
        # Update VM position
        vmac_old = self.vmac_manager.get_vm_vmac(mac)
        self.vm_manager.update_position(mac, self.dcenter_id, dpid_new,
                                        port_new)

        if dcenter_old != self.dcenter_id:
            # Multi-datacenter migration
            # A new vmac has not been created
            # Revoke old vm_id
            vm_id_old = self.vm_manager.revoke_vm_id(mac, dpid_old)
            self.switch_manager.recollect_vm_id(vm_id_old, dpid_old)
            # Generate new vm_id
            vm_id_new = self.vm_manager.generate_vm_id(mac, dpid_new,
                                                       self.switch_manager)
            vmac_new = self.vmac_manager.create_vm_vmac(mac,
                                                        self.tenant_manager,
                                                        self.vm_manager)

            # Instruct other datacenter to operate accordingly
            self.rpc_manager.handle_dc_migration(mac, dcenter_old, dpid_old,
                                                 port_old, vm_id_old,
                                                 self.dcenter_id, dpid_new,
                                                 port_new, vm_id_new)

            # Set up flows at gateway to redirect flows bound for
            # old vmac in dcenter_old to new vmac
            # The flow will expire after ARP cache expires
            self.flow_manager.set_gateway_bounce_flow(dpid_new, vmac_new,
                                                      vmac_old, self.topology)

            # Add flow at dpid_new towards vmac_new
            self.flow_manager.set_local_flow(dpid_new, vmac_new, mac, port_new)
            LOGGER.info("Live migration: Add local forward flow on (switch=%s)"
                        "towards (mac=%s)", dpid_new, mac)

            self.notify_vmac_update(mac, vmac_old, vmac_new)
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
            # Revoke old vm_id
            vm_id_old = self.vm_manager.revoke_vm_id(mac, dpid_old)
            self.switch_manager.recollect_vm_id(vm_id_old, dpid_old)
            # Generate new vm_id
            vm_id_new = self.vm_manager.generate_vm_id(mac, dpid_new,
                                                       self.switch_manager)
            vmac_new = self.vmac_manager.create_vm_vmac(mac,
                                                        self.tenant_manager,
                                                        self.vm_manager)

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
            self.notify_vmac_update(mac, vmac_old, vmac_new)
            return

        if port_old != port_new:
            # Same switch, different port migration
            # Redirect traffic
            self.flow_manager.set_local_flow(dpid_old, vmac_old, mac, port_new,
                                             False)
            LOGGER.info("Update forward flow on (switch=%s) towards (mac=%s)",
                        dpid_old, mac)
            return

    def notify_vmac_update(self, mac, vmac_old, vmac_new):
        # Send gratuitous ARP to all local guests sending traffic to mac
        for mac_query in self.vmac_manager.get_query_macs(vmac_old):
            ip = self.arp_manager.get_ip(mac)
            ip_query = self.arp_manager.get_ip(mac_query)
            self.inception_arp.send_arp_reply(ip, vmac_new, ip_query,
                                              mac_query)
        self.vmac_manager.del_vmac_query(vmac_old)
