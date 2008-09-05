import re

# From http://www.cymru.com/Documents/bogon-list.html
_bogon_list ="""
0.0.0.0/7
2.0.0.0/8
5.0.0.0/8
10.0.0.0/8
14.0.0.0/8
23.0.0.0/8
27.0.0.0/8
31.0.0.0/8
36.0.0.0/7
39.0.0.0/8
42.0.0.0/8
46.0.0.0/8
49.0.0.0/8
50.0.0.0/8
100.0.0.0/6
104.0.0.0/5
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
175.0.0.0/8
176.0.0.0/5
184.0.0.0/7
192.0.2.0/24
192.168.0.0/16
197.0.0.0/8
198.18.0.0/15
223.0.0.0/8
224.0.0.0/3
"""

_ip = r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})"
_re_ip = re.compile(r"^%s$" % _ip)
_re_ip_range = re.compile(r"^(?P<ip>%s)/(?P<mask>\d+)$" % _ip)

class BadIPError(Exception):
    pass


def ip_to_int(ip):
    try:
        ip_ints = [int(i) for i in _re_ip.match(ip).groups()]
    except:
        raise BadIPError()
    if len(ip_ints) != 4 or max(ip_ints) > 255:
        raise BadIPError()
    return ip_ints[0] << 24 | ip_ints[1] << 16 | ip_ints[2] << 8 | ip_ints[3]

def read_bogons(it):
    bogons = []
    for range in it:
        match = _re_ip_range.match(range)
        if match is not None:
            bogons.append((ip_to_int(match.group("ip")), int(match.group("mask"))))
    return bogons

def is_routable_ip(ip):
    try:
        ip_int = ip_to_int(ip)
    except BadIPError:
        return False
    for bogon_ip, mask in _bogons:
        if ip_int >> (32 - mask) == bogon_ip >> (32 - mask):
            return False
    return True

_bogons = read_bogons(_bogon_list.split("\n"))
__all__ = ["is_routable_ip"]
