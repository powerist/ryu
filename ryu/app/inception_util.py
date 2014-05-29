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

from ryu.app import inception_conf as i_conf

LOGGER = logging.getLogger(__name__)

"""Inception utilities"""


def tuple_to_str(data_tuple, sep=','):
    """Convert tuple to string."""

    data_string = sep.join(data_tuple)
    return data_string


def str_to_tuple(data_string, sep=','):
    """Convert string to tuple."""

    data_tuple = tuple(data_string.split(sep))
    return data_tuple


def extract_ip_addr(ip_prefix, port_name):
    """Extract IP address from port name"""

    _, ip_suffix1, ip_suffix2 = port_name.split('_')
    peer_ip = '.'.join((ip_prefix, ip_suffix1, ip_suffix2))

    return peer_ip


def parse_peer_dcenters(peer_dcenters, out_sep=';', in_sep=','):
    """Convert string to dictionary"""

    peer_dcs_list = peer_dcenters.split(out_sep)
    peer_dcs_dic = {}
    for peer_dc in peer_dcs_list:
        peer_list = peer_dc.split(in_sep)
        peer_dcs_dic[peer_list[0]] = (peer_list[1], peer_list[2])

    return peer_dcs_dic


def parse_tenants(tenant_info, out_sep=';', in_sep=','):
    """Convert string to list of tuples"""
    if tenant_info == None:
        return None

    tenant_str_list = tenant_info.split(out_sep)
    tenant_list = []
    for tenant_str in tenant_str_list:
        mac_list = tenant_str.split(in_sep)
        mac_tuple = tuple(mac_list)
        tenant_list.append(mac_tuple)

    return tenant_list


def generate_vm_id(vm_mac, dpid, conflict_record):
    """Generate a new vm_id,
    00 is saved for switch"""
    #TODO(chen): Avoid hash conflict
    vm_id = (hash(vm_mac) % i_conf.VM_MAXID + 1)
    if conflict_record[dpid][vm_id]:
        LOGGER.info("ERROR: switch id conflict: ", vm_id)
    else:
        conflict_record[dpid][vm_id] = True

    return vm_id


# TODO(chen): Class VMAC
def create_dc_vmac(dcenter):
    """Generate MAC address for datacenter based on datacenter id.

    Address form: xx:xx:00:00:00:00
    xx:xx is converted from data center id
    """
    if dcenter > 65535:
        return

    dcenter_high = (dcenter >> 8) & 0xff
    dcenter_low = dcenter & 0xff
    dcenter_vmac = "%02x:%02x:00:00:00:00" % (dcenter_high, dcenter_low)
    return dcenter_vmac


def create_swc_vmac(dcenter_vmac, dpid, conflict_record):
    """Generate MAC address prefix for switch based on
    datacenter id and switch id.

    Address form: xx:xx:yy:yy:00:00
    xx:xx is converted from data center id
    yy:yy is converted from switch id
    """
    dcenter_prefix = get_dc_prefix(dcenter_vmac)

    switch_num = (hash(dpid) % i_conf.SWITCH_MAXID) + 1
    if conflict_record[switch_num]:
        LOGGER.info("ERROR: switch id conflict: ", switch_num)
    else:
        conflict_record[switch_num] = True

    switch_high = (switch_num >> 8) & 0xff
    switch_low = switch_num & 0xff
    switch_suffix = ("%02x:%02x:00:00" % (switch_high, switch_low))
    return ':'.join((dcenter_prefix, switch_suffix))


def create_vm_vmac(switch_vmac, vm_id, tenant_id):
    """Generate virtual MAC address of a VM"""

    switch_prefix = get_swc_prefix(switch_vmac)
    vm_id_hex = vm_id & 0xff
    vm_id_suffix = "%02x" % vm_id_hex
    tenant_id_hex = tenant_id & 0xff
    tenant_id_suffix = "%02x" % tenant_id_hex
    return ':'.join((switch_prefix, vm_id_suffix, tenant_id_suffix))


def get_swc_prefix(vmac):
    """Extract switch prefix from virtual MAC address"""
    return vmac[:11]


def get_dc_prefix(vmac):
    """Extract switch prefix from virtual MAC address"""
    return vmac[:5]
