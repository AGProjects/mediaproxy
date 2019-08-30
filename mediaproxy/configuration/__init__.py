
from application.configuration import ConfigSection, ConfigSetting
from application.configuration.datatypes import IPAddress, NetworkRangeList
from application.system import host

from mediaproxy import configuration_file
from mediaproxy.configuration.datatypes import AccountingModuleList, DispatcherIPAddress, DispatcherAddressList, DispatcherManagementAddress, PortRange, PositiveInteger, SIPThorDomain, X509NameValidator


class DispatcherConfig(ConfigSection):
    __cfgfile__ = configuration_file
    __section__ = 'Dispatcher'

    socket_path = 'dispatcher.sock'
    listen = ConfigSetting(type=DispatcherIPAddress, value=DispatcherIPAddress('any'))
    listen_management = ConfigSetting(type=DispatcherManagementAddress, value=DispatcherManagementAddress('any'))
    relay_timeout = 5            # How much to wait for an answer from a relay
    relay_recover_interval = 60  # How much to wait for an unresponsive relay to recover, before disconnecting it
    cleanup_dead_relays_after = 43200       # 12 hours
    cleanup_expired_sessions_after = 86400  # 24 hours
    management_use_tls = True
    accounting = ConfigSetting(type=AccountingModuleList, value=[])
    passport = ConfigSetting(type=X509NameValidator, value=None)
    management_passport = ConfigSetting(type=X509NameValidator, value=None)


class RelayConfig(ConfigSection):
    __cfgfile__ = configuration_file
    __section__ = 'Relay'

    relay_ip = ConfigSetting(type=IPAddress, value=host.default_ip)
    advertised_ip = ConfigSetting(type=IPAddress, value=None)
    stream_timeout = 90
    on_hold_timeout = 7200
    traffic_sampling_period = 15
    userspace_transmit_every = 1
    dispatchers = ConfigSetting(type=DispatcherAddressList, value=[])
    port_range = PortRange('50000:60000')
    dns_check_interval = PositiveInteger(60)
    keepalive_interval = PositiveInteger(10)
    reconnect_delay = PositiveInteger(10)
    passport = ConfigSetting(type=X509NameValidator, value=None)
    routable_private_ranges = ConfigSetting(type=NetworkRangeList, value=[])


class OpenSIPSConfig(ConfigSection):
    __cfgfile__ = configuration_file
    __section__ = 'OpenSIPS'

    socket_path = '/run/opensips/socket'
    location_table = 'location'


class RadiusConfig(ConfigSection):
    __cfgfile__ = configuration_file
    __section__ = 'Radius'

    config_file = '/etc/opensips/radius/client.conf'
    additional_dictionary = 'radius/dictionary'


class DatabaseConfig(ConfigSection):
    __cfgfile__ = configuration_file
    __section__ = 'Database'

    dburi = ''
    sessions_table = 'media_sessions'
    callid_column = 'call_id'
    fromtag_column = 'from_tag'
    totag_column = 'to_tag'
    info_column = 'info'


class TLSConfig(ConfigSection):
    __cfgfile__ = configuration_file
    __section__ = 'TLS'

    certs_path = 'tls'
    verify_interval = 300


class ThorNetworkConfig(ConfigSection):
    __cfgfile__ = configuration_file
    __section__ = 'ThorNetwork'

    domain = ConfigSetting(type=SIPThorDomain, value=None)
    node_ip = host.default_ip
