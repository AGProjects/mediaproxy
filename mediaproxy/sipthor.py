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

from thor.control import ControlLink
from thor.entities import ThorEntitiesRoleMap, GenericThorEntity as ThorEntity
from thor.eventservice import EventServiceClient, ThorEvent
from thor.tls import X509Credentials

from mediaproxy import configuration_filename

class ThorNetworkConfig(ConfigSection):
    domain = "sipthor.net"
    nodeIP = default_host_ip
    multiply = 1000

configuration = ConfigFile(configuration_filename)
configuration.read_settings("ThorNetwork", ThorNetworkConfig)

class SIPThorMediaRelayBase(EventServiceClient):
    topics = ["Thor.Members"]
    
    def __init__(self):
        self.node = ThorEntity(ThorNetworkConfig.nodeIP, ["mprelay_server"])
        self.networks = {}
        self.presence_message = ThorEvent('Thor.Presence', self.node.id)
        self.shutdown_message = ThorEvent('Thor.Leave', self.node.id)
        credentials = X509Credentials(cert_name='mprelay')
        credentials.session_params.compressions = (COMP_LZO, COMP_DEFLATE, COMP_NULL)
        self.control = ControlLink(credentials)
        EventServiceClient.__init__(self, ThorNetworkConfig.domain, credentials)

    def _disconnect_all(self, result):
        self.control.disconnect_all()
        EventServiceClient._disconnect_all(self, result)

    def handle_event(self, event):
        networks = self.networks
        role_map = ThorEntitiesRoleMap(event.message) ## mapping between role names and lists of nodes with that role
        all_roles = role_map.keys() + networks.keys()
        for role in all_roles:
            try:
                network = networks[role] ## avoid setdefault here because it always evaluates the 2nd argument
            except KeyError:
                from thor import network as thor_network
                if role in ["thor_manager", "thor_monitor", "provisioning_server", "media_relay"]:
                    continue
                else:
                    network = thor_network.new(ThorNetworkConfig.multiply)
                networks[role] = network
            new_nodes = set([node.ip for node in role_map.get(role, [])])
            old_nodes = set(network.nodes)
            ## compute set differences
            added_nodes = new_nodes - old_nodes
            removed_nodes = old_nodes - new_nodes
            if removed_nodes:
                for node in removed_nodes:
                    network.remove_node(node)
                    self.control.discard_node(node)
                plural = len(removed_nodes) != 1 and 's' or ''
                log.msg("removed %s node%s: %s" % (role, plural, ', '.join(removed_nodes)))
            if added_nodes:
                for node in added_nodes:
                    network.add_node(node)
                plural = len(added_nodes) != 1 and 's' or ''
                log.msg("added %s node%s: %s" % (role, plural, ', '.join(added_nodes)))
        network = self.networks.get("sip_proxy", None)
        if network is None:
            self.update_dispatchers([])
        else:
            print network.nodes
            self.update_dispatchers(network.nodes)

    def update_dispatchers(self, dispatchers):
        raise NotImplementedError()

    def _handle_SIGHUP(self, *args):
        log.msg("Received SIGHUP, shutting down after all sessions have expired.")
        reactor.callFromThread(self.shutdown, False)

    def _handle_SIGINT(self, *args):
        if process._daemon:
            log.msg("Received SIGINT, shutting down.")
        else:
            log.msg("Received KeyboardInterrupt, exiting.")
        reactor.callFromThread(self.shutdown, True)

    def _handle_SIGTERM(self, *args):
        log.msg("Received SIGTERM, shutting down.")
        reactor.callFromThread(self.shutdown, True)

    def shutdown(self, kill_sessions):
        pass
