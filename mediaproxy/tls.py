
"""TLS support"""

__all__ = ['X509Credentials']

import os
import stat

from application.process import process
from gnutls import crypto
from gnutls.interfaces import twisted

from mediaproxy.configuration import TLSConfig


class FileDescriptor(object):
    def __init__(self, name, type):
        certs_path = os.path.normpath(TLSConfig.certs_path)
#        print(f"Tls config from {certs_path}")
        self.path = os.path.join(certs_path, name)
        self.klass = type
        self.timestamp = 0
        self.object = None
    def get(self):
        path = process.configuration.file(self.path)
        if path is None:
            raise RuntimeError('missing or unreadable file: %s' % self.path)
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
        raise AttributeError('cannot set attribute')

    def __delete__(self, obj):
        raise AttributeError('cannot delete attribute')


class X509Certificate(X509Entity):
    type = crypto.X509Certificate


class X509PrivateKey(X509Entity):
    type = crypto.X509PrivateKey


class X509CRL(X509Entity):
    type = crypto.X509CRL


class X509Credentials(twisted.X509Credentials):
    """SIPThor X509 credentials"""

    X509cert_name = None  # will be defined by each instance
    X509key_name  = None  # will be defined by each instance
    X509ca_name   = 'ca.pem'
    X509crl_name  = 'crl.pem'

    X509cert = X509Certificate(name_attr='X509cert_name')
    X509key  = X509PrivateKey(name_attr='X509key_name')
    X509ca   = X509Certificate(name_attr='X509ca_name')
    X509crl  = X509CRL(name_attr='X509crl_name')

    def __init__(self, cert_name):
        self.X509cert_name = '%s.crt' % cert_name
        self.X509key_name = '%s.key' % cert_name
#        print(f"cert file called {cert_name}")
        twisted.X509Credentials.__init__(self, self.X509cert, self.X509key, [self.X509ca], [self.X509crl])
        self.verify_peer = True
        self.verify_period = TLSConfig.verify_interval
