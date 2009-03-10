# Copyright (C) 2008 AG-Projects.
#

"""Mediaproxy implements a media relay for SIP calls"""

__version__ = "2.3.2"

system_config_directory = '/etc/mediaproxy'
runtime_directory = '/var/run/mediaproxy'

configuration_filename = 'config.ini'

default_dispatcher_port = 25060
default_management_port = 25061

class LogLevel(str):
    def __new__(typ, value):
        from application import log
        try:
            return getattr(log.level, value.upper())
        except AttributeError:
            raise ValueError("Not a valid log level: %s" % value)
