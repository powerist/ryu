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

"""A global view of priorities for each type of traffic/flow, to ease
management.
"""

# The priorities are sorted in a descending order, which is by design

ARP = 2000

DHCP = 1900

HOST_BCAST = 1800

SWITCH_BCAST = 1700

DATA_FWD_TENANT = 1600
DATA_FWD_DCENTER = 1500
DATA_FWD_LOCAL = 1400
DATA_FWD_SWITCH = 1300

NORMAL = 1000
