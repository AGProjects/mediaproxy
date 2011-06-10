# Copyright (C) 2007-2008 AG Projects.
#

"""TLS support"""

__all__ = ['X509Credentials', 'X509NameValidator']

import os
import stat
import re

from gnutls import crypto
from gnutls.interfaces import twisted

from application.process import process
from application.configuration import ConfigSection

from mediaproxy import configuration_filename


class TLSConfig(ConfigSection):
    __cfgfile__ = configuration_filename
    __section__ = 'TLS'

    certs_path = 'tls'
    verify_interval = 300



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


class FileDescriptor(object):
    def __init__(self, name, type):
        certs_path = os.path.normpath(TLSConfig.certs_path)
        self.path = os.path.join(certs_path, name)
        self.klass = type
        self.timestamp = 0
        self.object = None
    def get(self):
        path = process.config_file(self.path)
        if path is None:
            raise RuntimeError("missing or unreadable file: %s" % self.path)
        mtime = os.stat(path)[stat.ST_MTIME]
        if self.timestamp < mtime:
            f = open(path)
            try:
                self.object = self.klass(f.read())
                self.timestamp = mtime
            finally:
                f.close()
        return self.object


class X509Entity(object):
    type = None
    def __init__(self, name_attr):
        self.name_attr = name_attr
        self.descriptors = {}
    def __get__(self, obj, type_=None):
        name = getattr(obj or type_, self.name_attr, None)
        if name is None:
            return None
        descriptor = self.descriptors.setdefault(name, FileDescriptor(name, self.type))
        return descriptor.get()
    def __set__(self, obj, value):
        raise AttributeError("cannot set attribute")
    def __delete__(self, obj):
        raise AttributeError("cannot delete attribute")


class X509Certificate(X509Entity):
    type = crypto.X509Certificate

class X509PrivateKey(X509Entity):
    type = crypto.X509PrivateKey

class X509CRL(X509Entity):
    type = crypto.X509CRL


class X509Credentials(twisted.X509Credentials):
    """SIPThor X509 credentials"""

    X509cert_name = None ## will be defined by each instance
    X509key_name  = None ## will be defined by each instance
    X509ca_name   = 'ca.pem'
    X509crl_name  = 'crl.pem'

    X509cert = X509Certificate(name_attr='X509cert_name')
    X509key  = X509PrivateKey(name_attr='X509key_name')
    X509ca   = X509Certificate(name_attr='X509ca_name')
    X509crl  = X509CRL(name_attr='X509crl_name')

    def __init__(self, cert_name):
        self.X509cert_name = '%s.crt' % cert_name
        self.X509key_name = '%s.key' % cert_name
        twisted.X509Credentials.__init__(self, self.X509cert, self.X509key, [self.X509ca], [self.X509crl])
        self.verify_peer = True
        self.verify_period = TLSConfig.verify_interval

