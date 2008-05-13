#
# Copyright (C) 2008 AG Projects
# Author: Ruud Klaver <ruud@ag-projects.com>
#

from twisted.internet import reactor

from application import log
from application.configuration import *
from application.system import default_host_ip
from application.process import process

from gnutls.constants import *

from thor.entities import ThorEntities, GenericThorEntity
from thor.eventservice import EventServiceClient, ThorEvent
from thor.tls import X509Credentials

from mediaproxy.relay import SRVMediaRelayBase
from mediaproxy import configuration_filename, default_dispatcher_port

class ThorNetworkConfig(ConfigSection):
    domain = "sipthor.net"
    nodeIP = default_host_ip
    multiply = 1000

configuration = ConfigFile(configuration_filename)
configuration.read_settings("ThorNetwork", ThorNetworkConfig)

class SIPThorMediaRelayBase(EventServiceClient, SRVMediaRelayBase):
    topics = ["Thor.Members"]

    def __init__(self):
        self.node = GenericThorEntity(ThorNetworkConfig.nodeIP, ["media_relay"])
        self.presence_message = ThorEvent('Thor.Presence', self.node.id)
        self.shutdown_message = ThorEvent('Thor.Leave', self.node.id)
        credentials = X509Credentials(cert_name='node')
        credentials.session_params.compressions = (COMP_LZO, COMP_DEFLATE, COMP_NULL)
        self.sipthor_dispatchers = []
        self.additional_dispatchers = []
        EventServiceClient.__init__(self, ThorNetworkConfig.domain, credentials)
        SRVMediaRelayBase.__init__(self)

    def handle_event(self, event):
        sip_proxy_ips = [node.ip for node in ThorEntities(event.message, role="sip_proxy")]
        self.sipthor_dispatchers = [(ip, default_dispatcher_port) for ip in sip_proxy_ips]
        if not self.shutting_down:
            self.update_dispatchers(self.sipthor_dispatchers + self.additional_dispatchers)

    def _do_update(self, dispatchers):
        self.additional_dispatchers = dispatchers
        if not self.shutting_down:
            self.update_dispatchers(self.sipthor_dispatchers + self.additional_dispatchers)

    def update_dispatchers(self, dispatchers):
        raise NotImplementedError()

    def _handle_SIGHUP(self, *args):
        SRVMediaRelayBase._handle_SIGHUP(self, *args)
        #log.msg("Received SIGHUP, shutting down after all sessions have expired.")
        #reactor.callFromThread(self.shutdown, False)

    def _handle_SIGINT(self, *args):
        SRVMediaRelayBase._handle_SIGINT(self, *args)
        #if process._daemon:
        #    log.msg("Received SIGINT, shutting down.")
        #else:
        #    log.msg("Received KeyboardInterrupt, exiting.")
        #reactor.callFromThread(self.shutdown, True)

    def _handle_SIGTERM(self, *args):
        SRVMediaRelayBase._handle_SIGTERM(self, *args)
        #log.msg("Received SIGTERM, shutting down.")
        #reactor.callFromThread(self.shutdown, True)

    def shutdown(self, kill_sessions):
        raise NotImplementedError()
