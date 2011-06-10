# Copyright (C) 2008 AG-Projects.
#

"""Mediaproxy implements a media relay for SIP calls"""

__version__ = "2.4.4"

system_config_directory = '/etc/mediaproxy'
runtime_directory = '/var/run/mediaproxy'

configuration_filename = 'config.ini'

default_dispatcher_port = 25060
default_management_port = 25061


package_requirements = {'python-application': '1.2.8',
                        'python-gnutls':      '1.1.8',
                        'twisted':            '2.5.0'}

try:
    from application.dependency import ApplicationDependencies, DependencyError
except ImportError:
    class DependencyError(Exception): pass

    class ApplicationDependencies(object):
        def __init__(self, *args, **kw):
            pass
        def check(self):
            required_version = package_requirements['python-application']
            raise DependencyError("need python-application version %s or higher but it's not installed" % required_version)

dependencies = ApplicationDependencies(**package_requirements)

