"""A global view of priorities for each type of traffic/flow, to ease
management.
"""

# The priorities are sorted in a descending order, which is by design
ARP = 2000
DHCP = 1900
HOST_BCAST = 1800
SWITCH_BCAST = 1700
DATA_FWD = 1500
NORMAL = 1000
