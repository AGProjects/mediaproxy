
import re

from application.configuration.datatypes import IPAddress, NetworkAddress, StringList
from gnutls import crypto


class DispatcherIPAddress(NetworkAddress):
    default_port = 25060


class DispatcherManagementAddress(NetworkAddress):
    default_port = 25061


class AccountingModuleList(StringList):
    _valid_backends = {'database', 'radius'}

    def __new__(cls, value):
        proposed_backends = set(StringList.__new__(cls, value))
        return list(proposed_backends & cls._valid_backends)


class DispatcherAddress(tuple):
    default_port = 25060

    def __new__(cls, value):
        match = re.search(r"^(?P<address>.+?):(?P<port>\d+)$", value)
        if match:
            address = str(match.group("address"))
            port = int(match.group("port"))
        else:
            address = value
            port = cls.default_port
        try:
            address = IPAddress(address)
            is_domain = False
        except ValueError:
            is_domain = True
        return tuple.__new__(cls, (address, port, is_domain))


class DispatcherAddressList(list):
    def __init__(cls, value):
        list.__init__(cls, (DispatcherAddress(dispatcher) for dispatcher in re.split(r'\s*,\s*|\s+', value)))


class PortRange(object):
    """A port range in the form start:end with start and end being even numbers in the [1024, 65536] range"""
    def __init__(self, value):
        self.start, self.end = [int(p) for p in value.split(':', 1)]
        allowed = range(1024, 65537, 2)
        if not (self.start in allowed and self.end in allowed and self.start < self.end):
            raise ValueError("bad range: %r: ports must be even numbers in the range [1024, 65536] with start < end" % value)
    def __repr__(self):
        return "%s('%d:%d')" % (self.__class__.__name__, self.start, self.end)


class PositiveInteger(int):
    def __new__(cls, value):
        instance = int.__new__(cls, value)
        if instance < 1:
            raise ValueError("value must be a positive integer")
        return instance


class SIPThorDomain(str):
    """A SIP Thor domain name or the keyword None"""
    def __new__(cls, name):
        if name is None:
            return None
        elif not isinstance(name, str):
            raise TypeError("domain name must be a string, unicode or None")
        if name.lower() == 'none':
            return None
        return name


class X509NameValidator(crypto.X509Name):
    def __new__(cls, dname):
        if dname.lower() == 'none':
            return None
        return crypto.X509Name.__new__(cls, dname)

    def __init__(self, dname):
        str.__init__(self)
        pairs = [x.replace('\,', ',') for x in re.split(r'(?<!\\),\s*', dname)]
        for pair in pairs:
            try:
                name, value = pair.split(':', 1)
            except ValueError:
                raise ValueError("Invalid certificate access list: %s" % dname)
            if name not in self.ids:
                raise ValueError("Invalid authorization attribute: %s", name)
            str.__setattr__(self, name, value)
        for name in crypto.X509Name.ids:
            if not hasattr(self, name):
                str.__setattr__(self, name, None)

    def accept(self, cert):
        for id in self.ids:
            validator_attr = getattr(self, id)
            if validator_attr is not None:
                cert_attr = getattr(cert.subject, id)
                if validator_attr[0] == '*':
                    if not cert_attr.endswith(validator_attr[1:]):
                        return False
                elif validator_attr[-1] == '*':
                    if not cert_attr.startswith(validator_attr[:-1]):
                        return False
                elif validator_attr != cert_attr:
                    return False
        return True
