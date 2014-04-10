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

"""Inception utilities"""


def tuple_to_str(data_tuple, sep=','):
    """Convert tuple to string."""

    data_string = sep.join(data_tuple)
    return data_string


def str_to_tuple(data_string, sep=','):
    """Convert string to tuple."""

    data_tuple = tuple(data_string.split(sep))
    return data_tuple


def generate_vm_id(last_id, bound=65535):
    """Generate a new vm_id,
    00 is saved for switch"""
    #TODO(chen): Avoid id conflict
    return ((last_id + 1) % 65534 + 1)


# TODO(chen): Class VMAC
def create_swc_vmac(dcenter, switch_num):
    """Generate MAC address prefix for switch based on
    datacenter id and switch id.

    Address form: xx:xx:yy:yy:00:00
    xx:xx is converted from data center id
    yy:yy is converted from switch id
    """
    if dcenter > 65535 and switch_num > 65535:
        # Invalid numbers
        return

    dcenter_high = (dcenter >> 8) & 0xff
    dcenter_low = dcenter & 0xff
    dcenter_prefix = "%02x:%02x" % (dcenter_high, dcenter_low)

    switch_high = (switch_num >> 8) & 0xff
    switch_low = switch_num & 0xff
    switch_suffix = ("%02x:%02x:00:00" % (switch_high, switch_low))
    return ':'.join((dcenter_prefix, switch_suffix))


def create_vm_vmac(switch_vmac, vm_id):
    """Generate virtual MAC address of a VM"""

    switch_prefix = get_swc_prefix(switch_vmac)
    id_hex = vm_id & 0xff
    id_suffix = "%02x" % id_hex
    return ':'.join((switch_prefix, id_suffix, '00'))


def get_swc_prefix(vmac):
    """Extract switch prefix from virtual MAC address"""
    return vmac[:11]


def get_dc_prefix(vmac):
    """Extract switch prefix from virtual MAC address"""
    return vmac[:5]
