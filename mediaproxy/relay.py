# Copyright (C) 2008 AG Projects
# Author: Ruud Klaver <ruud@ag-projects.com>
#

"""Implementation of the MediaProxy relay"""


import cjson
import signal
import resource
import re
from time import time

import twisted
from twisted.python.versions import Version
needed_version = Version('twisted', 2, 5, 0)
if twisted.version < needed_version:
    have_version, want_version = twisted.__version__, needed_version.short()
    raise RuntimeError("the twisted framework should be at least version %s (found %s)" % (want_version, have_version))

try:    from twisted.internet import epollreactor; epollreactor.install()
except: raise RuntimeError("mandatory epoll reactor support is missing from the twisted framework")

from twisted.protocols.basic import LineOnlyReceiver
from twisted.internet.error import ConnectionDone, TCPTimedOutError, DNSLookupError
from twisted.internet.protocol import ClientFactory
from twisted.internet.defer import DeferredList, succeed
from twisted.internet import reactor
from twisted.python import failure
from twisted.names import dns
from twisted.names.client import lookupService
from twisted.names.error import DomainError

from gnutls.errors import CertificateError, CertificateSecurityError

from application import log
from application.configuration import *
from application.configuration.datatypes import IPAddress
from application.process import process
from application.system import default_host_ip

from mediaproxy.tls import X509Credentials, X509NameValidator
from mediaproxy.headers import DecodingDict, DecodingError
from mediaproxy.mediacontrol import SessionManager
from mediaproxy.scheduler import RecurrentCall, KeepRunning
from mediaproxy import __version__ as version, configuration_filename, default_dispatcher_port

IP_FORWARD_FILE = "/proc/sys/net/ipv4/ip_forward"
KERNEL_VERSION_FILE = "/proc/sys/kernel/osrelease"

class DispatcherAddress(tuple):
    def __new__(cls, value):
        match = re.search(r"^(?P<address>.+?):(?P<port>\d+)$", value)
        if match:
            address = str(match.group("address"))
            port = int(match.group("port"))
        else:
            address = value
            port = default_dispatcher_port
        try:
            address = datatypes.IPAddress(address)
            is_domain = False
        except ValueError:
            is_domain = True
        return (address, port, is_domain)

class DispatcherAddressList(list):
    def __new__(cls, value):
        return [DispatcherAddress(dispatcher) for dispatcher in value.split()]

class PortRange(object):
    """A port range in the form start:end with start and end being even numbers in the [1024, 65536] range"""
    def __init__(self, value):
        self.start, self.end = [int(p) for p in value.split(':', 1)]
        allowed = xrange(1024, 65537, 2)
        if not (self.start in allowed and self.end in allowed and self.start < self.end):
            raise ValueError("bad range: %r: ports must be even numbers in the range [1024, 65536] with start < end" % value)

class PositiveInteger(int):
    def __new__(cls, value):
        instance = int.__new__(cls, value)
        if instance < 1:
            raise ValueError("value must be a positive integer")
        return instance


class Config(ConfigSection):
    _datatypes = {'dispatchers': DispatcherAddressList, 'relay_ip': IPAddress, 'passport': X509NameValidator}
    dispatchers = []
    relay_ip = default_host_ip
    port_range = PortRange("50000:60000")
    dns_check_interval = PositiveInteger(60)
    keepalive_interval = PositiveInteger(10)
    reconnect_delay = PositiveInteger(10)
    passport = None


configuration = ConfigFile(configuration_filename)
configuration.read_settings("Relay", Config)

## Increase the system limit for the maximum number of open file descriptors
## to be able to handle connections to all ports in port_range
try:
    fd_limit = Config.port_range.end - Config.port_range.start + 1000
    resource.setrlimit(resource.RLIMIT_NOFILE, (fd_limit, fd_limit))
except ValueError:
    raise RuntimeError("Cannot set resource limit for maximum open file descriptors to %d" % fd_limit)
else:
    new_limits = resource.getrlimit(resource.RLIMIT_NOFILE)
    if new_limits < (fd_limit, fd_limit):
        raise RuntimeError("Allocated resource limit for maximum open file descriptors is less then requested (%d instead of %d)" % (new_limits[0], fd_limit))
    else:
        log.msg("Set resource limit for maximum open file descriptors to %d" % fd_limit)

class RelayClientProtocol(LineOnlyReceiver):
    noisy = False
    required_headers = {'update': set(['call_id', 'from_tag', 'from_uri', 'to_uri', 'cseq', 'user_agent', 'media', 'type']),
                        'remove': set(['call_id', 'from_tag']),
                        'summary': set(),
                        'sessions': set()}

    def __init__(self):
        self.command = None
        self.seq = None
        self._connection_watcher = None
        self._queued_keepalives = 0

    def _send_keepalive(self):
        if self._queued_keepalives >= 3:
            # 3 keepalives in a row didn't get an answer. assume connection is down.
            log.error("missed 3 keepalive answers in a row. assuming the connection is down.")
            # do not use loseConnection() as it waits to flush the output buffers.
            reactor.callLater(0, self.transport.connectionLost, failure.Failure(TCPTimedOutError()))
            return None
        self.transport.write("ping\r\n")
        self._queued_keepalives += 1
        return KeepRunning

    def connectionMade(self):
        peer = self.transport.getPeer()
        log.debug("Connected to dispatcher at %s:%d" % (peer.host, peer.port))
        if Config.passport is not None:
            peer_cert = self.transport.getPeerCertificate()
            if not Config.passport.accept(peer_cert):
                self.transport.loseConnection(CertificateSecurityError('peer certificate not accepted'))
        self._connection_watcher = RecurrentCall(Config.keepalive_interval, self._send_keepalive)

    def connectionLost(self, reason):
        if self._connection_watcher is not None:
            self._connection_watcher.cancel()
            self._connection_watcher = None
        self._queued_keepalives = 0

    def lineReceived(self, line):
        if line == 'pong':
            self._queued_keepalives -= 1
            return
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
                self.transport.write("%s error\r\n" % seq)
        elif line == "":
            try:
                missing_headers = self.required_headers[self.command].difference(self.headers)
                if missing_headers:
                    for header in missing_headers:
                        log.error("Missing mandatory header '%s' from '%s' command" % (header, self.command))
                    response = "error"
                else:
                    try:
                        response = self.factory.parent.got_command(self.factory.host, self.command, self.headers)
                    except:
                        log.err()
                        response = "error"
            finally:
                self.transport.write("%s %s\r\n" % (self.seq, response))
                self.command = None
        else:
            try:
                name, value = line.split(": ", 1)
            except ValueError:
                log.error("Unable to parse header: %s" % line)
            else:
                try:
                    self.headers[name] = value
                except DecodingError, e:
                    log.error("Could not decode header: %s" % e)


class DispatcherConnectingFactory(ClientFactory):
    noisy = False
    protocol = RelayClientProtocol

    def __init__(self, parent, host, port):
        self.parent = parent
        self.host = (host, port)
        self.delayed = None
        self.connection_lost = False

    def __eq__(self, other):
        return self.host == other.host

    def clientConnectionFailed(self, connector, reason):
        log.error('Could not connect to dispatcher at %(host)s:%(port)d (retrying in %%d seconds): %%s' % connector.__dict__ % (Config.reconnect_delay, reason.value))
        if self.parent.connector_needs_reconnect(connector):
            self.delayed = reactor.callLater(Config.reconnect_delay, connector.connect)

    def clientConnectionLost(self, connector, reason):
        self.cancel_delayed()
        if reason.type != ConnectionDone:
            log.error("Connection with dispatcher at %(host)s:%(port)d was lost: %%s" % connector.__dict__ % reason.value)
        else:
            log.msg("Connection with dispatcher at %(host)s:%(port)d was closed" % connector.__dict__)
        if self.parent.connector_needs_reconnect(connector):
            if isinstance(reason.value, CertificateError) or self.connection_lost:
                self.delayed = reactor.callLater(Config.reconnect_delay, connector.connect)
            else:
                self.delayed = reactor.callLater(min(Config.reconnect_delay, 1), connector.connect)
            self.connection_lost = True

    def buildProtocol(self, addr):
        self.delayed = reactor.callLater(5, self._connected_successfully)
        return ClientFactory.buildProtocol(self, addr)

    def _connected_successfully(self):
        self.connection_lost = False

    def cancel_delayed(self):
        if self.delayed:
            if self.delayed.active():
                self.delayed.cancel()
            self.delayed = None


class SRVMediaRelayBase(object):

    def __init__(self):
        self.srv_monitor = RecurrentCall(Config.dns_check_interval, self._do_lookup)
        self._do_lookup()

    def _do_lookup(self):
        defers = []
        for addr, port, is_domain in Config.dispatchers:
            if is_domain:
                defer = lookupService("_sip._udp.%s" % addr)
                defer.addCallback(self._cb_got_srv, port)
                defer.addErrback(self._eb_no_srv, addr, port)
                defers.append(defer)
            else:
                defers.append(succeed((addr, port)))
        defer = DeferredList(defers)
        defer.addCallback(self._cb_got_all)
        return KeepRunning

    def _cb_got_srv(self, (answers, auth, add), port):
        for answer in answers:
            if answer.type == dns.SRV and answer.payload and answer.payload.target != dns.Name("."):
                return str(answer.payload.target), port
        raise DomainError

    def _eb_no_srv(self, failure, addr, port):
        failure.trap(DomainError)
        return reactor.resolve(addr).addCallback(lambda host: (host, port)).addErrback(self._eb_no_dns, addr)

    def _eb_no_dns(self, failure, addr):
        failure.trap(DNSLookupError)
        log.error("Could resolve neither SRV nor A record for '%s'" % addr)

    def _cb_got_all(self, results):
        if not self.shutting_down:
            dispatchers = [result[1] for result in results if result[0] and result[1] is not None]
            self.update_dispatchers(dispatchers)

    def update_dispatchers(self, dispatchers):
        raise NotImplementedError()

    def run(self):
        process.signals.add_handler(signal.SIGHUP, self._handle_SIGHUP)
        process.signals.add_handler(signal.SIGINT, self._handle_SIGINT)
        process.signals.add_handler(signal.SIGTERM, self._handle_SIGTERM)
        reactor.run()

    def _handle_SIGHUP(self, *args):
        log.msg("Received SIGHUP, shutting down after all sessions have expired.")
        reactor.callFromThread(self.shutdown, graceful=True)

    def _handle_SIGINT(self, *args):
        if process._daemon:
            log.msg("Received SIGINT, shutting down.")
        else:
            log.msg("Received KeyboardInterrupt, exiting.")
        reactor.callFromThread(self.shutdown)

    def _handle_SIGTERM(self, *args):
        log.msg("Received SIGTERM, shutting down.")
        reactor.callFromThread(self.shutdown)

    def shutdown(self, graceful=False):
        raise NotImplementedError()

    def on_shutdown(self):
        pass

    def _shutdown(self):
        reactor.stop()
        self.on_shutdown()


try:
    from mediaproxy.sipthor import SIPThorMediaRelayBase
    MediaRelayBase = SIPThorMediaRelayBase
except ImportError:
    MediaRelayBase = SRVMediaRelayBase

class MediaRelay(MediaRelayBase):

    def __init__(self):
        try:
            ip_forward = bool(int(open(IP_FORWARD_FILE).read()))
        except:
            ip_forward = False
        if not ip_forward:
            raise RuntimeError("IP forwarding is not available or not enabled (check %s)" % IP_FORWARD_FILE)
        try:
            major, minor, revision = [int(num) for num in open(KERNEL_VERSION_FILE).read().split("-", 1)[0].split(".")[:3]]
        except:
            raise RuntimeError("Could not determine Linux kernel version")
        if (major, minor, revision) < (2, 6, 18):
            raise RuntimeError("A mimimum Linux kernel version of 2.6.18 is required")
        self.cred = X509Credentials(cert_name='relay')
        self.session_manager = SessionManager(self, Config.port_range.start, Config.port_range.end)
        self.dispatchers = set()
        self.dispatcher_session_count = {}
        self.dispatcher_connectors = {}
        self.old_connectors = {}
        self.shutting_down = False
        self.graceful_shutdown = False
        self.start_time = time()
        MediaRelayBase.__init__(self)

    @property
    def status(self):
        if self.graceful_shutdown or self.shutting_down:
            return 'halting'
        else:
            return 'active'

    def update_dispatchers(self, dispatchers):
        dispatchers = set(dispatchers)
        for new_dispatcher in dispatchers.difference(self.dispatchers):
            if new_dispatcher in self.old_connectors.iterkeys():
                log.debug('Restoring old dispatcher at %s:%d' % new_dispatcher)
                self.dispatcher_connectors[new_dispatcher] = self.old_connectors.pop(new_dispatcher)
            else:
                log.debug('Adding new dispatcher at %s:%d' % new_dispatcher)
                dispatcher_addr, dispatcher_port = new_dispatcher
                factory = DispatcherConnectingFactory(self, dispatcher_addr, dispatcher_port)
                self.dispatcher_connectors[new_dispatcher] = reactor.connectTLS(dispatcher_addr, dispatcher_port, factory, self.cred)
        for old_dispatcher in self.dispatchers.difference(dispatchers):
            log.debug('Removing old dispatcher at %s:%d' % old_dispatcher)
            self.old_connectors[old_dispatcher] = self.dispatcher_connectors.pop(old_dispatcher)
            self._check_disconnect(old_dispatcher)
        self.dispatchers = dispatchers

    def got_command(self, dispatcher, command, headers):
        if command == "summary":
            summary = {'ip'            : Config.relay_ip,
                       'version'       : version,
                       'status'        : self.status,
                       'uptime'        : int(time() - self.start_time),
                       'session_count' : len(self.session_manager.sessions),
                       'stream_count'  : self.session_manager.stream_count,
                       'bps_relayed'   : self.session_manager.bps_relayed}
            return cjson.encode(summary)
        elif command == "sessions":
            return cjson.encode(self.session_manager.statistics)
        elif command == "update":
            if self.graceful_shutdown or self.shutting_down:
                if not self.session_manager.has_session(**headers):
                    log.debug("cannot add new session: media-relay is shutting down")
                    return 'halting'
            local_media = self.session_manager.update_session(dispatcher, **headers)
            return " ".join([local_media[0][0]] + [str(media[1]) for media in local_media])
        else: # remove
            session = self.session_manager.remove_session(**headers)
            if session is None:
                return "error"
            else:
                return cjson.encode(session.statistics)

    def session_expired(self, session):
        connector = self.dispatcher_connectors.get(session.dispatcher)
        if connector is None:
            connector = self.old_connectors.get(session.dispatcher)
        if connector and connector.state == "connected":
            connector.transport.write(" ".join(["expired", cjson.encode(session.statistics)]) + "\r\n")
        else:
            log.warn("dispatcher for expired session is no longer online, statistics are lost!")

    def add_session(self, dispatcher):
        self.dispatcher_session_count[dispatcher] = self.dispatcher_session_count.get(dispatcher, 0) + 1

    def remove_session(self, dispatcher):
        self.dispatcher_session_count[dispatcher] -= 1
        if self.dispatcher_session_count[dispatcher] == 0:
            del self.dispatcher_session_count[dispatcher]
        if self.graceful_shutdown and not self.dispatcher_session_count:
            self.shutdown()
        elif dispatcher in self.old_connectors:
            self._check_disconnect(dispatcher)

    def _check_disconnect(self, dispatcher):
        connector = self.old_connectors[dispatcher]
        if self.dispatcher_session_count.get(dispatcher, 0) == 0:
            old_state = connector.state
            connector.factory.cancel_delayed()
            connector.disconnect()
            if old_state == "disconnected":
                del self.old_connectors[dispatcher]
                if self.shutting_down and len(self.dispatcher_connectors) + len(self.old_connectors) == 0:
                    self._shutdown()

    def connector_needs_reconnect(self, connector):
        if connector in self.dispatcher_connectors.values():
            return True
        else:
            for dispatcher, old_connector in self.old_connectors.items():
                if old_connector is connector:
                    if self.dispatcher_session_count.get(dispatcher, 0) > 0:
                        return True
                    else:
                        del self.old_connectors[dispatcher]
                        break
            if self.shutting_down:
                if len(self.old_connectors) == 0:
                    self._shutdown()
            return False

    def shutdown(self, graceful=False):
        if graceful:
            self.graceful_shutdown = True
            if self.dispatcher_session_count:
                return
        if not self.shutting_down:
            self.shutting_down = True
            self.srv_monitor.cancel()
            if len(self.dispatcher_connectors) + len(self.old_connectors) == 0:
                self._shutdown()
            else:
                self.update_dispatchers([])
            self.session_manager.cleanup()

    def on_shutdown(self):
        self.session_manager.cleanup()
