
"""SIP Thor backend"""

from application import log
from gnutls.interfaces.twisted import TLSContext

from thor.entities import ThorEntities, GenericThorEntity
from thor.eventservice import EventServiceClient, ThorEvent
from thor.tls import X509Credentials

from mediaproxy import __version__
from mediaproxy.configuration import ThorNetworkConfig
from mediaproxy.configuration.datatypes import DispatcherIPAddress
from mediaproxy.relay import SRVMediaRelayBase


if ThorNetworkConfig.domain is None:
    # SIP Thor is installed but disabled. Fake an ImportError to start in standalone media relay mode.
    log.warning('SIP Thor is installed but disabled from the configuration')
    raise ImportError('SIP Thor is disabled')


class SIPThorMediaRelayBase(EventServiceClient, SRVMediaRelayBase):
    topics = ['Thor.Members']

    def __init__(self):
        self.node = GenericThorEntity(ThorNetworkConfig.node_ip, ['media_relay'], version=__version__)
        self.presence_message = ThorEvent('Thor.Presence', self.node.id)
        self.shutdown_message = ThorEvent('Thor.Leave', self.node.id)
        self.sipthor_dispatchers = []
        self.additional_dispatchers = []
        credentials = X509Credentials(cert_name='relay')
        tls_context = TLSContext(credentials)
        EventServiceClient.__init__(self, ThorNetworkConfig.domain, tls_context)
        SRVMediaRelayBase.__init__(self)

    def handle_event(self, event):
        if not self.shutting_down:
            sip_proxy_ips = [node.ip for node in ThorEntities(event.message, role='sip_proxy')]
            self.sipthor_dispatchers = [(ip, DispatcherIPAddress.default_port) for ip in sip_proxy_ips]
            self.update_dispatchers(self.sipthor_dispatchers + self.additional_dispatchers)

    def _cb_got_all(self, results):
        if not self.shutting_down:
            self.additional_dispatchers = [result[1] for result in results if result[0] and result[1] is not None]
            self.update_dispatchers(self.sipthor_dispatchers + self.additional_dispatchers)

    def update_dispatchers(self, dispatchers):
        raise NotImplementedError()

    def _handle_SIGHUP(self, *args):
        SRVMediaRelayBase._handle_SIGHUP(self, *args)

    def _handle_SIGINT(self, *args):
        SRVMediaRelayBase._handle_SIGINT(self, *args)

    def _handle_SIGTERM(self, *args):
        SRVMediaRelayBase._handle_SIGTERM(self, *args)

    def _handle_SIGUSR1(self, *args):
        SRVMediaRelayBase._handle_SIGUSR1(self, *args)

    def shutdown(self, graceful=False):
        raise NotImplementedError()
