"""A global view of priorities for each type of traffic/flow, to ease
management.
"""

# The priorities are sorted in a descending order, which is by design
ARP = 20
DHCP = 19
HOST_BCAST = 18
SWITCH_BCAST = 17
DATA_FWD = 15
NORMAL = 10
