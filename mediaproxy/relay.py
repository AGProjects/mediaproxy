#
# Copyright (C) 2008 AG Projects
# Author: Ruud Klaver <ruud@ag-projects.com>
#

"""Implementation of the MediaProxy relay component"""


import cjson
import signal
import traceback

from twisted.protocols.basic import LineOnlyReceiver
from twisted.internet.protocol import ClientFactory
from twisted.internet import epollreactor
epollreactor.install()
from twisted.internet import reactor
from twisted.names import dns
from twisted.names.client import lookupService
from twisted.names.error import DNSNameError

from gnutls.interfaces.twisted import X509Credentials

from application import log
from application.configuration import *
from application.configuration.datatypes import IPAddress
from application.process import process

from mediaproxy.tls import Certificate, PrivateKey
from mediaproxy.headers import DecodingDict, DecodingError
from mediaproxy.mediacontrol import SessionManager
from mediaproxy import configuration_filename, default_dispatcher_port

class Config(ConfigSection):
    _datatypes = {"dispatcher_address": IPAddress, "certificate": Certificate, "private_key": PrivateKey, "ca": Certificate}
    dispatcher_address = None
    dispatcher_port = default_dispatcher_port
    start_port = 40000
    end_port = 50000
    certificate = None
    private_key = None
    ca = None
    domain = "example.com"
    srv_retry = 10
    srv_refresh = 60
    reconnect_delay = 30


configuration = ConfigFile(configuration_filename)
configuration.read_settings("Relay", Config)

class RelayClientProtocol(LineOnlyReceiver):
    noisy = False
    required_headers = { "update": ["call_id", "from_tag", "from_uri", "to_uri", "cseq", "user_agent", "media", "type"],
                         "remove": ["call_id", "from_tag"] }

    def __init__(self):
        self.command = None
        self.seq = None

    def connectionMade(self):
        log.debug("Connected to dispatcher %s" % self.transport.getPeer().host)

    def lineReceived(self, line):
        if self.command is None:
            try:
                command, seq = line.split()
            except ValueError:
                log.error("Could not decode command/sequence number pair from dispatcher: %s" % line)
                return
            if command in self.required_headers:
                self.command = command
                self.seq = seq
                self.headers = DecodingDict()
            else:
                log.error("Unknown command: %s" % command)
        elif line.strip() == "":
            for header in self.required_headers[self.command]:
                if header not in self.headers:
                    log.error('Required header "%s" for command "%s" not found' % (header, self.command))
                    return
            try:
                try:
                    response = self.factory.parent.got_command(self.factory.host, self.command, self.seq, self.headers)
                except:
                    traceback.print_exc()
                    response = "%s error\r\n" % self.seq
            finally:
                if response:
                    self.transport.write(response)
                self.command = None
        else:
            try:
                name, value = line.split(": ", 1)
            except ValueError:
                log.error("Unable to parse header: %s" % line)
            try:
                self.headers[name] = value
            except DecodingError, e:
                log.error("Could not decode header: %s" % e)


class DispatcherConnectingFactory(ClientFactory):
    noisy = False
    protocol = RelayClientProtocol

    def __init__(self, parent, host):
        self.parent = parent
        self.host = host
        self.delayed = None

    def __eq__(self, other):
        return self.host == other.host

    def clientConnectionFailed(self, connector, reason):
        log.error('Could not connect to dispatcher "%s" retrying in %d seconds: %s' % (self.host, Config.reconnect_delay, reason.getErrorMessage()))
        self.delayed = reactor.callLater(Config.reconnect_delay, connector.connect)

    def clientConnectionLost(self, connector, reason):
        log.error('Connection lost to dispatcher "%s": %s' % (self.host, reason.getErrorMessage()))
        if self.parent.connector_needs_reconnect(connector):
            connector.connect()

    def cancel_delayed(self):
        if self.delayed and self.delayed.active():
            self.delayed.cancel()


class SRVMediaRelayBase(object):

    def __init__(self):
        self._do_lookup()

    def _do_lookup(self):
        if Config.dispatcher_address is not None:
            self.update_dispatchers([Config.dispatcher_address])
        else:
            result = lookupService("_sip._udp.%s" % Config.domain)
            result.addCallback(self._cb_got_srv)
            result.addCallbacks(self.update_dispatchers, self._eb_no_srv)

    def _cb_got_srv(self, (answers, auth, add)):
        for answer in answers:
            if answer.type == dns.SRV and answer.payload and answer.payload.target != dns.Name("."):
                reactor.callLater(Config.srv_refresh, self._do_lookup)
                return [str(answer.payload.target)]
        raise DNSNameError

    def _eb_no_srv(self, failure):
        failure.trap(DNSNameError)
        log.error('Could not resolve SIP SRV record for domain "%s", retrying in %d seconds' % (Config.domain, Config.srv_retry))
        reactor.callLater(Config.srv_retry, self._do_lookup)

    def update_dispatchers(self, dispatchers):
        raise NotImplementedError()

    def run(self):
        process.signals.add_handler(signal.SIGHUP, self._handle_SIGHUP)
        process.signals.add_handler(signal.SIGINT, self._handle_SIGINT)
        process.signals.add_handler(signal.SIGTERM, self._handle_SIGTERM)
        reactor.run()

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
        raise NotImplementedError()

    def on_shutdown(self):
        pass

    def _shutdown(self):
        reactor.stop()
        self.on_shutdown()


try:
    from sipthor import SIPThorMediaRelayBase
    MediaRelayBase = SIPThorMediaRelayBase
except ImportError:
    MediaRelayBase = SRVMediaRelayBase

class MediaRelay(MediaRelayBase):

    def __init__(self):
        self.session_manager = SessionManager(self, Config.start_port, Config.end_port)
        self.cred = X509Credentials(Config.certificate, Config.private_key, [Config.ca])
        self.cred.verify_peer = True
        self.dispatchers = set()
        self.dispatcher_session_count = {}
        self.dispatcher_connectors = {}
        self.old_connectors = {}
        self.shutting_down = False
        MediaRelayBase.__init__(self)

    def update_dispatchers(self, dispatchers):
        if self.shutting_down:
            return
        dispatchers = set(dispatchers)
        for new_dispatcher in dispatchers.difference(self.dispatchers):
            log.debug('Adding new dispatcher "%s"' % new_dispatcher)
            factory = DispatcherConnectingFactory(self, new_dispatcher)
            self.dispatcher_connectors[new_dispatcher] = reactor.connectTLS(new_dispatcher, Config.dispatcher_port, factory, self.cred)
        for old_dispatcher in self.dispatchers.difference(dispatchers):
            log.debug('Removing old dispatcher "%s"' % old_dispatcher)
            self.old_connectors[old_dispatcher] = self.dispatcher_connectors.pop(old_dispatcher)
            self._check_disconnect(old_dispatcher)
        self.dispatchers = dispatchers

    def got_command(self, dispatcher, command, seq, headers):
        if command == "update":
            local_media = self.session_manager.update_session(dispatcher, **headers)
            if local_media is None:
                return "%s halting\r\n" % seq
            else:
                return " ".join([seq] + [local_media[0][0]] + [str(media[1]) for media in local_media]) + "\r\n"
        else: # remove
            session = self.session_manager.remove_session(**headers)
            return seq + " " + cjson.encode(session.statistics) + "\r\n"

    def session_expired(self, session):
        connector = self.dispatcher_connectors.get(session.dispatcher)
        if connector is None:
            connector = self.old_connectors.get(session.dispatcher)
        if connector and connector.state == "connected":
            connector.transport.write(" ".join(["expired", cjson.encode(session.statistics)]) + "\r\n")
        else:
            log.warn("dispatcher for expired session is no longer online, statistics are lost!")

    def add_session(self, dispatcher):
        if self.shutting_down:
            return False
        else:
            self.dispatcher_session_count[dispatcher] = self.dispatcher_session_count.get(dispatcher, 0) + 1
            return True

    def remove_session(self, dispatcher):
        self.dispatcher_session_count[dispatcher] -= 1
        if dispatcher in self.old_connectors:
            self._check_disconnect(dispatcher)

    def _check_disconnect(self, dispatcher):
        connector = self.old_connectors[dispatcher]
        if self.dispatcher_session_count.get(dispatcher, 0) == 0:
            old_state = connector.state
            connector.factory.cancel_delayed()
            connector.disconnect()
            if old_state != "connected":
                del self.old_connectors[dispatcher]
                if len(self.old_connectors) == 0:
                    self._shutdown()

    def connector_needs_reconnect(self, connector):
        if self.shutting_down:
            for dispatcher, old_connector in self.old_connectors.items():
                if old_connector is connector:
                    del self.old_connectors[dispatcher]
                    break
            if len(self.old_connectors) == 0:
                self._shutdown()
            return False
        else:
            for present_connector in self.dispatcher_connectors.values() + self.old_connectors.values():
                if present_connector is connector:
                    return True
            return False

    def shutdown(self, kill_sessions):
        if not self.shutting_down:
            if len(self.dispatcher_connectors) + len(self.old_connectors) == 0:
                self._shutdown()
            else:
                self.update_dispatchers([])
            self.shutting_down = True
        if kill_sessions:
            self.session_manager.cleanup()

    def on_shutdown(self):
        self.session_manager.cleanup()
