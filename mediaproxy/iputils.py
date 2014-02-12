# Copyright (C) 2008 AG Projects
#

"""IP address utilities"""

__all__ = ["is_routable_ip"]

import socket
import struct

from application.configuration.datatypes import NetworkRangeList

from mediaproxy.configuration import RelayConfig


# Non routable network addresses (RFC 3330)
#
_non_routable_netlist = [
    '0.0.0.0/8',
    '10.0.0.0/8',
    '127.0.0.0/8',
    '169.254.0.0/16',
    '172.16.0.0/12',
    '192.0.2.0/24',
    '192.168.0.0/16',
    '198.51.100.0/24',
    '203.0.113.0/24',
    '224.0.0.0/4',
    '255.255.255.255/32'
]

_non_routable_nets = NetworkRangeList(_non_routable_netlist)


def is_routable_ip(ip):
    try:
        ip_addr = struct.unpack('!L', socket.inet_aton(ip))[0]
    except:
        return False
    for netbase, mask in RelayConfig.routable_private_ranges:
        if (ip_addr & mask) == netbase:
            return True
    for netbase, mask in _non_routable_nets:
        if (ip_addr & mask) == netbase:
            return False
    return True

