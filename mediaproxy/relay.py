
"""Implementation of the MediaProxy relay"""

import json
import signal
import resource

"""
try:
    from twisted.internet import epollreactor; epollreactor.install()
except:
    raise RuntimeError('mandatory epoll reactor support is not available from the twisted framework')
"""

from application import log
from application.process import process
from gnutls.errors import CertificateError, CertificateSecurityError
from gnutls.interfaces.twisted import TLSContext
from time import time
from twisted.protocols.basic import LineOnlyReceiver
from twisted.protocols.policies import TimeoutMixin
from twisted.internet.error import ConnectionDone, TCPTimedOutError, DNSLookupError
from twisted.internet.protocol import ClientFactory, connectionDone
from twisted.internet.defer import DeferredList, succeed
from twisted.internet import reactor
from twisted.python import failure
from twisted.names import dns
from twisted.names.client import lookupService
from twisted.names.error import DomainError

from mediaproxy import __version__
from mediaproxy.configuration import RelayConfig, ThorNetworkConfig
from mediaproxy.headers import DecodingDict, DecodingError
from mediaproxy.mediacontrol import SessionManager, RelayPortsExhaustedError
from mediaproxy.scheduler import RecurrentCall, KeepRunning
from mediaproxy.tls import X509Credentials

try:
    from thor.eventservice import ThorEvent
except ImportError:
    pass

# Increase the system limit for the maximum number of open file descriptors
# to be able to handle connections to all ports in port_range

fd_limit = RelayConfig.port_range.end - RelayConfig.port_range.start + 1000
try:
    resource.setrlimit(resource.RLIMIT_NOFILE, (fd_limit, fd_limit))
except ValueError:
    raise RuntimeError('Cannot set resource limit for maximum open file descriptors to %d' % fd_limit)
else:
    new_limits = resource.getrlimit(resource.RLIMIT_NOFILE)
    if new_limits < (fd_limit, fd_limit):
        raise RuntimeError("Allocated resource limit for maximum open file descriptors is less then requested (%d instead of %d)" % (new_limits[0], fd_limit))
    else:
        log.info('Set resource limit for maximum open file descriptors to %d' % fd_limit)


class RelayClientProtocol(LineOnlyReceiver, TimeoutMixin):
    noisy = False
    required_headers = {'update': {'call_id', 'from_tag', 'from_uri', 'to_uri', 'cseq', 'user_agent', 'type'},
                        'remove': {'call_id', 'from_tag'},
                        'summary': set(),
                        'sessions': set()}

    def __init__(self):
        self.command = None
        self.seq = None
        self.headers = DecodingDict()
        self._connection_watcher = None
        self._queued_keepalives = 0

    def _send_keepalive(self):
        if self._queued_keepalives >= 3:
            log.error('missed 3 keepalive answers in a row. assuming the connection is down.')
            # do not use loseConnection() as it waits to flush the output buffers.
            reactor.callLater(0, self.transport.connectionLost, failure.Failure(TCPTimedOutError()))
            return None
        self.transport.write(b'ping' + self.delimiter)
        self._queued_keepalives += 1
        return KeepRunning

    def reply(self, reply):
        log.debug(f"Send reply: {reply} to {self.transport.getPeer().host}:{self.transport.getPeer().port}")
        self.transport.write(reply.encode() + self.delimiter)

    def connectionMade(self):
        peer = self.transport.getPeer()
        certificate = self.transport.getPeerCertificate()
        subject = certificate.subject
        common_name = subject.common_name

        if RelayConfig.passport is not None:
            if not RelayConfig.passport.accept(certificate):
                log.error("Connection to relay %s at %s:%d refused due to wrong passport" % (common_name, peer.host, peer.port))
                self.transport.loseConnection()
                return
            log.info('Relay connected to dispatcher %s at %s:%d' % (common_name, peer.host, peer.port))
        else:
            log.info('Relay connected to dispatcher %s at %s:%d' % (common_name, peer.host, peer.port))

        self._connection_watcher = RecurrentCall(RelayConfig.keepalive_interval, self._send_keepalive)

    def connectionLost(self, reason=connectionDone):
        if self._connection_watcher is not None:
            self._connection_watcher.cancel()
            self._connection_watcher = None
        self._queued_keepalives = 0

    def lineReceived(self, line):
        line = line.decode()
        log.debug(f"Line received: {line} from {self.transport.getPeer().host}:{self.transport.getPeer().port}")
        if line == 'pong':
            self._queued_keepalives -= 1
            return
        if self.command is None:
            try:
                command, seq = line.split()
            except ValueError:
                log.error('Could not decode command/sequence number pair from dispatcher: %s' % line)
                return
            if command in self.required_headers:
                self.command = command
                self.seq = seq
                self.headers = DecodingDict()
            else:
                log.error('Unknown command: %s' % command)
                self.reply('{} error'.format(seq))
        elif line == '':
            missing_headers = self.required_headers[self.command].difference(self.headers)
            if missing_headers:
                for header in missing_headers:
                    log.error('Missing mandatory header %r from %r command' % (header, self.command))
                response = 'error'
            else:
                # noinspection PyBroadException
                try:
                    response = self.factory.parent.got_command(self.factory.host, self.command, self.headers)
                except Exception:
                    log.exception()
                    response = 'error'
            self.reply('{} {}'.format(self.seq, response))
            self.command = None
        else:
            try:
                name, value = line.split(": ", 1)
            except ValueError:
                log.error('Unable to parse header: %s' % line)
            else:
                try:
                    self.headers[name] = value
                except DecodingError as e:
                    log.error('Could not decode header: %s' % e)


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
        log.error('Could not connect to dispatcher at %(host)s:%(port)d (retrying in %%d seconds): %%s' % connector.__dict__ % (RelayConfig.reconnect_delay, reason.value))
        if self.parent.connector_needs_reconnect(connector):
            self.delayed = reactor.callLater(RelayConfig.reconnect_delay, connector.connect)

    def clientConnectionLost(self, connector, reason):
        self.cancel_delayed()
#        if reason.type != ConnectionDone:
        log.error('Connection with dispatcher at %(host)s:%(port)d was lost: %%s' % connector.__dict__ % reason.value)
#        else:
#            log.info('Connection with dispatcher at %(host)s:%(port)d was closed' % connector.__dict__)
        if self.parent.connector_needs_reconnect(connector):
            if isinstance(reason.value, CertificateError) or self.connection_lost:
                self.delayed = reactor.callLater(RelayConfig.reconnect_delay, connector.connect)
            else:
                self.delayed = reactor.callLater(min(RelayConfig.reconnect_delay, 1), connector.connect)
            self.connection_lost = True

    def buildProtocol(self, addr):
        self.delayed = reactor.callLater(5, self._connected_successfully)
        return ClientFactory.buildProtocol(self, addr)

    def _connected_successfully(self):
        log.debug('Connected successfully')
        self.connection_lost = False

    def cancel_delayed(self):
        if self.delayed:
            if self.delayed.active():
                self.delayed.cancel()
            self.delayed = None


class SRVMediaRelayBase(object):
    def __init__(self):
        self.shutting_down = False
        self.srv_monitor = RecurrentCall(RelayConfig.dns_check_interval, self._do_lookup)
        self._do_lookup()

    def _do_lookup(self):
        defers = []
        if not RelayConfig.dispatchers and not ThorNetworkConfig.domain:
             log.error('No dispatcher(s) defined in config.ini')
             return

        for addr, port, is_domain in RelayConfig.dispatchers:
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

    def _cb_got_srv(self, answ_auth_add, port):
        (answers, auth, add) = answ_auth_add
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
        process.signals.add_handler(signal.SIGHUP, self._handle_signal)
        process.signals.add_handler(signal.SIGINT, self._handle_signal)
        process.signals.add_handler(signal.SIGTERM, self._handle_signal)
        process.signals.add_handler(signal.SIGUSR1, self._handle_signal)
        reactor.run(installSignalHandlers=False)

    def stop(self, graceful=False):
        reactor.callFromThread(self._shutdown, graceful=graceful)

    def _handle_signal(self, signum, frame):
        if signum == signal.SIGUSR1:
            # toggle debugging
            if log.level.current != log.level.DEBUG:
                log.level.current = log.level.DEBUG
                log.info('Switched logging level to DEBUG')
            else:
                log.info('Switched logging level to {}'.format(RelayConfig.log_level))
                log.level.current = RelayConfig.log_level
        else:
            # terminate program
            signal_map = {signal.SIGTERM: 'Terminated', signal.SIGINT: 'Interrupted', signal.SIGHUP: 'Graceful shutdown'}
            log.info(signal_map.get(signum, 'Received signal {}, exiting.'.format(signum)))
            self.stop(graceful=(signum == signal.SIGHUP))

    def _shutdown(self, graceful=False):
        raise NotImplementedError()

    @staticmethod
    def _shutdown_done():
        reactor.stop()


MediaRelayBase = SRVMediaRelayBase

try:
    if ThorNetworkConfig.domain is not None:
        if not RelayConfig.dispatchers:
            log.info('Using dispatchers discovered using SIP Thor for domain %s' % ThorNetworkConfig.domain)
            from mediaproxy.sipthor import SIPThorMediaRelayBase as MediaRelayBase
        else:
            log.info('Using dispatchers defined in config.ini')
            MediaRelayBase = SRVMediaRelayBase
except ImportError:
    pass


class MediaRelay(MediaRelayBase):
    def __init__(self):
        self.cred = X509Credentials(cert_name='relay')
        self.tls_context = TLSContext(self.cred)
        self.session_manager = SessionManager(self, RelayConfig.port_range.start, RelayConfig.port_range.end)
        self.dispatchers = set()
        self.dispatcher_session_count = {}
        self.dispatcher_connectors = {}
        self.old_connectors = {}
        self.shutting_down = False
        self.graceful_shutdown = False
        self.start_time = time()
        super().__init__()

    @property
    def status(self):
        if self.graceful_shutdown or self.shutting_down:
            return 'halting'
        else:
            return 'active'

    def update_dispatchers(self, dispatchers):
        dispatchers = set(dispatchers)
        for new_dispatcher in dispatchers.difference(self.dispatchers):
            if new_dispatcher in iter(self.old_connectors.keys()):
                log.info('Restoring old dispatcher at %s:%d' % new_dispatcher)
                self.dispatcher_connectors[new_dispatcher] = self.old_connectors.pop(new_dispatcher)
            else:
                log.info('Adding new dispatcher at %s:%d' % new_dispatcher)
                dispatcher_addr, dispatcher_port = new_dispatcher
                factory = DispatcherConnectingFactory(self, dispatcher_addr, dispatcher_port)
                self.dispatcher_connectors[new_dispatcher] = reactor.connectTLS(dispatcher_addr,
                                                                                dispatcher_port,
                                                                                factory,
                                                                                self.tls_context)
        for old_dispatcher in self.dispatchers.difference(dispatchers):
            try:
                self.old_connectors[old_dispatcher] = self.dispatcher_connectors.pop(old_dispatcher)
            except KeyError:
                pass
            else:
                log.info('Removing old dispatcher at %s:%d' % old_dispatcher)
                self._check_disconnect(old_dispatcher)
        self.dispatchers = dispatchers

    def _TH_publish_statistics(self, task):
        statistics = {'media_relay': {'sessions': len(self.session_manager.sessions),
                                      'bad_sessions': len(self.session_manager.broken_sessions),
                                      'bps_relayed': int(self.session_manager.bps_relayed),
                                      'ports': len(self.session_manager.ports),
                                      'bad_ports': len(self.session_manager.bad_ports),
                                      'versions': {'relay': __version__},
                                      'status': self.status
                                      }
                      }
        message = dict(ip=self.node.ip, statistics=statistics)
        self._publish(ThorEvent('Thor.Statistics', message))

    def got_command(self, dispatcher, command, headers):
        if command == 'summary':
            summary = {'ip': RelayConfig.relay_ip,
                       'version': __version__,
                       'status': self.status,
                       'uptime': int(time() - self.start_time),
                       'session_count': len(self.session_manager.sessions),
                       'stream_count': self.session_manager.stream_count,
                       'bps_relayed': self.session_manager.bps_relayed}
            return json.dumps(summary)
        elif command == 'sessions':
            return json.dumps(self.session_manager.statistics)
        elif command == 'update':
            if self.graceful_shutdown or self.shutting_down:
                if not self.session_manager.has_session(**headers):
                    log.info('cannot add new session: media-relay is shutting down')
                    return 'halting'
            try:
                local_media = self.session_manager.update_session(dispatcher, **headers)
            except RelayPortsExhaustedError:
                log.error('Could not reserve relay ports for session, all allocated ports are being used')
                return 'error'
            if local_media:
                return ' '.join([RelayConfig.advertised_ip or local_media[0][0]] + [str(media[1]) for media in local_media])
        else:  # command == 'remove'
            session = self.session_manager.remove_session(**headers)
            if session is None:
                return 'error'
            else:
                return json.dumps(session.statistics)

    def session_expired(self, session):
        connector = self.dispatcher_connectors.get(session.dispatcher)
        if connector is None:
            connector = self.old_connectors.get(session.dispatcher)
        if connector:
            if connector.state == 'connected':
                reply = ' '.join(['expired', json.dumps(session.statistics)])
                log.debug(f"Send expire for session {session.call_id} to dispatcher {connector.transport.getPeer().host}:{connector.transport.getPeer().port}: {reply}")
                connector.transport.write(reply.encode() + connector.factory.protocol.delimiter)
            else:
                log.warning('dispatcher {connector.transport.getPeer().host}:{connector.transport.getPeer().port} for expired session {session.call_id} is no longer online, statistics are lost!')
        else:
            log.warning('dispatcher for expired session {session.call_id} is no longer online, statistics are lost!')

    def add_session(self, dispatcher):
        self.dispatcher_session_count[dispatcher] = self.dispatcher_session_count.get(dispatcher, 0) + 1

    def remove_session(self, dispatcher):
        self.dispatcher_session_count[dispatcher] -= 1
        if self.dispatcher_session_count[dispatcher] == 0:
            del self.dispatcher_session_count[dispatcher]
        if self.graceful_shutdown and not self.dispatcher_session_count:
            self._shutdown()
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
                    self._shutdown_done()

    def connector_needs_reconnect(self, connector):
        if connector in list(self.dispatcher_connectors.values()):
            return True
        else:
            for dispatcher, old_connector in list(self.old_connectors.items()):
                if old_connector is connector:
                    if self.dispatcher_session_count.get(dispatcher, 0) > 0:
                        return True
                    else:
                        del self.old_connectors[dispatcher]
                        break
            if self.shutting_down:
                if len(self.old_connectors) == 0:
                    self._shutdown_done()
            return False

    def _shutdown(self, graceful=False):
        if graceful:
            self.graceful_shutdown = True
            if self.dispatcher_session_count:
                return
        if not self.shutting_down:
            self.shutting_down = True
            self.srv_monitor.cancel()
            self.session_manager.cleanup()
            if len(self.dispatcher_connectors) + len(self.old_connectors) == 0:
                self._shutdown_done()
            else:
                self.update_dispatchers([])
