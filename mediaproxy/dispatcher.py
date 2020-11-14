
"""Implementation of the MediaProxy dispatcher"""

import hashlib
import random
import signal
import pickle as pickle
import json
from json import JSONDecodeError

from base64 import b64encode as base64_encode
from collections import deque

from time import time

from application import log
from application.process import process
from application.system import unlink
from gnutls.errors import CertificateSecurityError
from gnutls.interfaces.twisted import TLSContext, listenTLS
from twisted.protocols.basic import LineOnlyReceiver
from twisted.python import failure
from twisted.internet.error import ConnectionDone, TCPTimedOutError
from twisted.internet.protocol import Factory, connectionDone
from twisted.internet.defer import Deferred, DeferredList, maybeDeferred, succeed
from twisted.internet import reactor

from mediaproxy import __version__
from mediaproxy.configuration import DispatcherConfig
from mediaproxy.interfaces import opensips
from mediaproxy.scheduler import RecurrentCall, KeepRunning
from mediaproxy.tls import X509Credentials


class CommandError(Exception):
    pass


class Command(object):
    def __init__(self, name, headers=None):
        self.name = name
        self.headers = headers or []
        try:
            self.parsed_headers = dict(header.split(': ', 1) for header in self.headers)
        except Exception:
            raise CommandError('Could not parse command headers')
        else:
            if self.call_id:
                self.__dict__['session_id'] = base64_encode(hashlib.md5(self.call_id.encode()).digest()).rstrip(b'=')
            else:
                self.__dict__['session_id'] = None

    @property
    def call_id(self):
        return self.parsed_headers.get('call_id')

    @property
    def dialog_id(self):
        return self.parsed_headers.get('dialog_id')

    @property
    def session_id(self):
        return self.__dict__['session_id']


class ProtocolLogger(log.ContextualLogger):
    def __init__(self, name):
        super(ProtocolLogger, self).__init__(logger=log.get_logger())  # use the main logger as backend
        self.name = name

    def apply_context(self, message):
        return '[{0}] {1}'.format(self.name, message) if message != '' else ''


class SessionLogger(log.ContextualLogger):
    def __init__(self, session):
        super(SessionLogger, self).__init__(logger=log.get_logger())  # use the main logger as backend
        self.session_id = session.call_id
        self.relay_ip = session.relay_ip

    def apply_context(self, message):
        return '[session {0.session_id} at {0.relay_ip}] {1}'.format(self, message) if message != '' else ''


class ControlProtocol(LineOnlyReceiver):
    logger = None  # type: ProtocolLogger
    noisy = False

    def __init__(self):
        self.in_progress = 0
        self.delimiter = b'\r\n'

    def lineReceived(self, line):
        self.logger.debbug('Line received: ', line)
        raise NotImplementedError()

    def connectionLost(self, reason):
#        if isinstance(reason.value, connectionDone.type):
#            self.logger.info('Connection closed')
#        else:
        self.logger.warning('Connection lost: {}'.format(reason.value))
        self.factory.connection_lost(self)

    def reply(self, reply):
        self.transport.write(reply.encode() + self.delimiter)

    def _error_handler(self, failure):
        failure.trap(CommandError, RelayError)
        self.logger.error(failure.value)
        self.reply('error')

    def _catch_all(self, failure):
        self.logger.error(failure.getTraceback())
        self.reply('error')

    def _decrement(self, result):
        self.in_progress = 0
        if self.factory.shutting_down:
            self.transport.loseConnection()

    def _add_callbacks(self, defer):
        defer.addCallback(self.reply)
        defer.addErrback(self._error_handler)
        defer.addErrback(self._catch_all)
        defer.addBoth(self._decrement)


class OpenSIPSControlProtocol(ControlProtocol):
    logger = ProtocolLogger(name='OpenSIPS Interface')

    def __init__(self):
        self.request_lines = []
        ControlProtocol.__init__(self)

    def lineReceived(self, line):
        line = line.decode()
        if line == '':
            if self.request_lines:
                self.in_progress += 1
                defer = maybeDeferred(self.handle_request, self.request_lines)
                self._add_callbacks(defer)
                self.request_lines = []
        elif not line.endswith(': '):
            self.request_lines.append(line)

    def handle_request(self, request_lines):
        command = Command(name=request_lines[0], headers=request_lines[1:])
        if command.call_id is None:
            raise CommandError('Request is missing the call_id header')
        return self.factory.dispatcher.send_command(command)


class ManagementControlProtocol(ControlProtocol):
    logger = ProtocolLogger(name='Management Interface')

    def connectionMade(self):
        if DispatcherConfig.management_use_tls and DispatcherConfig.management_passport is not None:
            peer_cert = self.transport.getPeerCertificate()
            log.debug(f"peer {self.transport.getPeer().host}:{self.transport.getPeer().port} {peer_cert.subject}")
            if not DispatcherConfig.management_passport.accept(peer_cert):
                self.transport.loseConnection()
                return

    def lineReceived(self, line):
        line = line.decode()
        if line in ['quit', 'exit']:
            self.transport.loseConnection()
        elif line == 'summary':
            defer = self.factory.dispatcher.relay_factory.get_summary()
            self._add_callbacks(defer)
        elif line == 'sessions':
            defer = self.factory.dispatcher.relay_factory.get_statistics()
            self._add_callbacks(defer)
        elif line == 'version':
            self.reply(__version__)
        else:
            self.logger.error('Unknown command: %s' % line)
            self.reply('error')


class ControlFactory(Factory):
    noisy = False

    def __init__(self, dispatcher):
        self.dispatcher = dispatcher
        self.protocols = []
        self.shutting_down = False

    def buildProtocol(self, addr):
        protocol = Factory.buildProtocol(self, addr)
        self.protocols.append(protocol)
        return protocol

    def connection_lost(self, prot):
        self.protocols.remove(prot)
        if self.shutting_down and len(self.protocols) == 0:
            self.defer.callback(None)

    def shutdown(self):
        if self.shutting_down:
            return
        self.shutting_down = True
        if len(self.protocols) == 0:
            return succeed(None)
        else:
            for prot in self.protocols:
                if prot.in_progress == 0:
                    prot.transport.loseConnection()
            self.defer = Deferred()
            return self.defer


class OpenSIPSControlFactory(ControlFactory):
    protocol = OpenSIPSControlProtocol


class ManagementControlFactory(ControlFactory):
    protocol = ManagementControlProtocol


class RelayError(Exception):
    pass


class ConnectionReplaced(ConnectionDone):
    pass


class RelayServerProtocol(LineOnlyReceiver):
    MAX_LENGTH = 4096*1024  # 4MB
    noisy = False

    def __init__(self):
        self.ip = None      # type: str
        self.logger = None  # type: ProtocolLogger
        self.commands = {}
        self.halting = False
        self.timedout = False
        self.disconnect_timer = None
        self.sequence_number = 0
        self.authenticated = False

    @property
    def active(self):
        return not self.halting and not self.timedout

    def send_command(self, command):
        if command.call_id:
            self.logger.info('Requesting {0.name!r} for session {0.session_id}'.format(command))
        else:
            self.logger.info('Requesting {0.name!r}'.format(command))
        sequence_number = str(self.sequence_number)
        self.sequence_number += 1
        defer = Deferred()
        timer = reactor.callLater(DispatcherConfig.relay_timeout, self._timeout, sequence_number)
        self.commands[sequence_number] = (command, defer, timer)
        to_write = [elem.encode() for elem in ['{} {}'.format(command.name, sequence_number)] + command.headers]
        self.transport.write(self.delimiter.join(to_write) + 2 * self.delimiter)
        return defer

    def reply(self, reply):
        log.debug(f"Send reply: {reply.decode()} to {self.transport.getPeer().host}:{self.transport.getPeer().port}") 
        self.transport.write(reply + self.delimiter)

    def _timeout(self, sequence_number):
        command, defer, timer = self.commands.pop(sequence_number)
        defer.errback(RelayError('%r command failed: relay at %s timed out' % (command.name, self.ip)))
        if self.timedout is False:
            self.timedout = True
            self.disconnect_timer = reactor.callLater(DispatcherConfig.relay_recover_interval, self.transport.connectionLost, failure.Failure(TCPTimedOutError()))

    def connectionMade(self):
        if DispatcherConfig.passport is not None:
            peer_cert = self.transport.getPeerCertificate()
            if not DispatcherConfig.passport.accept(peer_cert):
                log.error(f"Refuse connection from {self.transport.getPeer().host}:{self.transport.getPeer().port} with invalid passport {peer_cert.subject}")
                self.transport.loseConnection()
                return
        self.authenticated = True
        self.factory.new_relay(self)

    def lineReceived(self, line):
        line = line.decode()
        log.debug(f"Line received: {line} from {self.transport.getPeer().host}:{self.transport.getPeer().port}")
        try:
            first, rest = line.split(' ', 1)
        except ValueError:
            first = line
            rest = ''
        if first == 'expired':
            try:
                stats = json.loads(rest)
            except JSONDecodeError as e:
                self.logger.error('Could not decode JSON: {}'.format(e))
            else:
                call_id = stats['call_id']
                session = self.factory.sessions.get(call_id, None)
                if session is None:
                    self.logger.error('Expired session has unknown call_id %s' % call_id)
                    return
                if session.relay_ip != self.ip:
                    session.logger.error('relay at %s reported the session as expired, ignoring' % self.ip)
                    return
                all_streams_ice = all(stream_info['status'] == 'unselected ICE candidate' for stream_info in stats['streams'])
                if all_streams_ice:
                    session.logger.info('removed because ICE was used')
                    stats['timed_out'] = False
                else:
                    session.logger.info('did timeout')
                    stats['timed_out'] = True
                stats['dialog_id'] = session.dialog_id
                stats['all_streams_ice'] = all_streams_ice
                self.factory.dispatcher.update_statistics(session, stats)
                if session.dialog_id is not None and stats['start_time'] is not None and not all_streams_ice:
                    self.factory.dispatcher.opensips_management.end_dialog(session.dialog_id)
                    session.expire_time = time()
                else:
                    del self.factory.sessions[call_id]
            return
        elif first == 'ping':
            if self.timedout is True:
                self.timedout = False
                if self.disconnect_timer.active():
                    self.disconnect_timer.cancel()
                self.disconnect_timer = None
            self.reply(b'pong')
            return
        try:
            command, defer, timer = self.commands.pop(first)
        except KeyError:
            self.logger.error('Got unexpected response: {}'.format(line))
            return
        timer.cancel()
        if rest == 'error':
            defer.errback(RelayError('Relay replied with error'))
        elif rest == 'halting':
            self.halting = True
            defer.errback(RelayError('Relay is shutting down'))
        elif command.name == 'remove':
            try:
                stats = json.loads(rest)
            except JSONDecodeError:
                self.logger.error('Error decoding JSON')
            else:
                call_id = stats['call_id']
                session = self.factory.sessions[call_id]
                stats['dialog_id'] = session.dialog_id
                stats['timed_out'] = False
                self.factory.dispatcher.update_statistics(session, stats)
                del self.factory.sessions[call_id]
            defer.callback('removed')
        else:  # update command
            defer.callback(rest)

    def connectionLost(self, reason):
#        if reason.type == ConnectionDone:
#            self.logger.info('Connection closed')
#        elif reason.type == ConnectionReplaced:
#            self.logger.warning('Connection replaced')
#        else:
        self.logger.error('Connection lost: {}'.format(reason.value))
        for command, defer, timer in self.commands.values():
            timer.cancel()
            defer.errback(RelayError('Relay disconnected'))
        if self.timedout is True:
            self.timedout = False
            if self.disconnect_timer.active():
                self.disconnect_timer.cancel()
            self.disconnect_timer = None
        self.factory.connection_lost(self)


class RelaySession(object):
    def __init__(self, relay, command):
        self.relay_ip = relay.ip
        self.call_id = command.call_id
        self.session_id = command.session_id
        self.dialog_id = command.dialog_id
        self.logger = SessionLogger(self)
        self.expire_time = None

    def __getstate__(self):
        state = self.__dict__.copy()
        del state['logger']
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self.logger = SessionLogger(self)


class RelayFactory(Factory):
    protocol = RelayServerProtocol
    noisy = False

    def __init__(self, dispatcher):
        self.dispatcher = dispatcher
        self.relays = {}
        self.shutting_down = False
        state_file = process.runtime.file('dispatcher_state')
        try:
            self.sessions = pickle.load(open(state_file))
        except Exception:
            self.sessions = {}
            self.cleanup_timers = {}
        else:
            self.cleanup_timers = dict((ip, reactor.callLater(DispatcherConfig.cleanup_dead_relays_after, self._do_cleanup, ip)) for ip in set(session.relay_ip for session in self.sessions.values()))
        unlink(state_file)
        self.expired_cleaner = RecurrentCall(600, self._remove_expired_sessions)

    def _remove_expired_sessions(self):
        now, limit = time(), DispatcherConfig.cleanup_expired_sessions_after
        obsolete = [k for k, s in filter(lambda k_s: k_s[1].expire_time and (now-k_s[1].expire_time>=limit), iter(self.sessions.items()))]
        if obsolete:
            [self.sessions.pop(call_id) for call_id in obsolete]
            log.warning('found %d expired sessions which were not removed during the last %d hours' % (len(obsolete), round(limit / 3600.0)))
        return KeepRunning

    def buildProtocol(self, addr):
        protocol = Factory.buildProtocol(self, addr)
        protocol.ip = addr.host
        protocol.logger = ProtocolLogger(name='relay {}'.format(addr.host))
        protocol.logger.info('Connection established')
        return protocol

    def new_relay(self, relay):
        old_relay = self.relays.pop(relay.ip, None)
        if old_relay is not None:
            relay.logger.warning('Reconnected, closing old connection')
            reactor.callLater(0, old_relay.transport.connectionLost, failure.Failure(ConnectionReplaced('relay reconnected')))
        self.relays[relay.ip] = relay
        timer = self.cleanup_timers.pop(relay.ip, None)
        if timer is not None:
            timer.cancel()
        defer = relay.send_command(Command('sessions'))
        defer.addCallback(self._cb_purge_sessions, relay.ip)

    def _cb_purge_sessions(self, result, relay_ip):
        relay_sessions = json.loads(result)
        relay_call_ids = [session['call_id'] for session in relay_sessions]
        for session_id, session in list(self.sessions.items()):
            if session.expire_time is None and session.relay_ip == relay_ip and session_id not in relay_call_ids:
                session.logger.warning('Relay does not have the session anymore, statistics are probably lost')
                if session.dialog_id is not None:
                    self.dispatcher.opensips_management.end_dialog(session.dialog_id)
                del self.sessions[session_id]

    def send_command(self, command):
        session = self.sessions.get(command.call_id, None)
        if session and session.expire_time is None:
            relay = session.relay_ip
            if relay not in self.relays:
                session.logger.error('Request {0.name!r} failed: relay no longer connected'.format(command))
                raise RelayError('Request {0.name!r} failed: relay no longer connected'.format(command))
            return self.relays[relay].send_command(command)
        # We do not have a session for this call_id or the session is already expired
        if command.name == 'update':
            preferred_relay = command.parsed_headers.get('media_relay')
            try_relays = deque(protocol for protocol in self.relays.values() if protocol.active and protocol.ip != preferred_relay)
            random.shuffle(try_relays)
            if preferred_relay is not None:
                protocol = self.relays.get(preferred_relay)
                if protocol is not None and protocol.active:
                    try_relays.appendleft(protocol)
                else:
                    log.warning('user requested media_relay %s is not available' % preferred_relay)
            defer = self._try_next(try_relays, command)
            defer.addCallback(self._add_session, try_relays, command)
            return defer
        elif command.name == 'remove' and session:
            # This is the remove we received for an expired session for which we triggered dialog termination
            del self.sessions[command.call_id]
            return 'removed'
        else:
            raise RelayError('Got {0.name!r} for unknown session {0.session_id}'.format(command))

    def _add_session(self, result, try_relays, command):
        self.sessions[command.call_id] = RelaySession(try_relays[0], command)
        return result

    def _relay_error(self, failure, try_relays, command):
        failure.trap(RelayError)
        failed_relay = try_relays.popleft()
        failed_relay.logger.warning('The {0.name!r} request failed: {1.value}'.format(command, failure))
        return self._try_next(try_relays, command)

    def _try_next(self, try_relays, command):
        if len(try_relays) == 0:
            raise RelayError('No suitable relay found')
        defer = try_relays[0].send_command(command)
        defer.addErrback(self._relay_error, try_relays, command)
        return defer

    def get_summary(self):
        command = Command('summary')
        defer = DeferredList([relay.send_command(command).addErrback(self._summary_error, command, relay) for relay in self.relays.values()])
        defer.addCallback(self._got_summaries)
        return defer

    def _summary_error(self, failure, command, relay):
        relay.logger.error('The {0.name!r} request failed: {1.value}'.format(command, failure))
        return json.dumps(dict(status='error', ip=relay.ip))

    def _got_summaries(self, results):
        return '[%s]' % ', '.join(result for succeeded, result in results if succeeded)

    def get_statistics(self):
        command = Command('sessions')
        defer = DeferredList([relay.send_command(command).addErrback(self._statistics_error, command, relay) for relay in self.relays.values()])
        defer.addCallback(self._got_statistics)
        return defer

    def _statistics_error(self, failure, command, relay):
        relay.logger.error('The {0.name!r} request failed: {1.value}'.format(command, failure))
        return json.loads([])

    def _got_statistics(self, results):
        return '[%s]' % ', '.join(result[1:-1] for succeeded, result in results if succeeded and result != '[]')

    def connection_lost(self, relay):
        if relay not in iter(self.relays.values()):
            return
        if relay.authenticated:
            del self.relays[relay.ip]
        if self.shutting_down:
            if len(self.relays) == 0:
                self.defer.callback(None)
        else:
            self.cleanup_timers[relay.ip] = reactor.callLater(DispatcherConfig.cleanup_dead_relays_after, self._do_cleanup, relay.ip)

    def _do_cleanup(self, ip):
        log.debug('Cleaning up after old relay at %s' % ip)
        del self.cleanup_timers[ip]
        for call_id in (call_id for call_id, session in list(self.sessions.items()) if session.relay_ip == ip):
            del self.sessions[call_id]

    def shutdown(self):
        if self.shutting_down:
            return
        self.shutting_down = True
        for timer in self.cleanup_timers.values():
            timer.cancel()
        if len(self.relays) == 0:
            retval = succeed(None)
        else:
            for prot in self.relays.values():
                prot.transport.loseConnection()
            self.defer = Deferred()
            retval = self.defer
        retval.addCallback(self._save_state)
        return retval

    def _save_state(self, result):
        pickle.dump(self.sessions, open(process.runtime.file('dispatcher_state'), 'wb'))


class Dispatcher(object):
    def __init__(self):
        self.accounting = [__import__('mediaproxy.interfaces.accounting.%s' % mod.lower(), globals(), locals(), ['']).Accounting() for mod in set(DispatcherConfig.accounting)]
        self.cred = X509Credentials(cert_name='dispatcher')
        self.tls_context = TLSContext(self.cred)
        self.relay_factory = RelayFactory(self)
        dispatcher_addr, dispatcher_port = DispatcherConfig.listen
        self.relay_listener = listenTLS(reactor, dispatcher_port, self.relay_factory, self.tls_context, interface=dispatcher_addr)
        self.opensips_factory = OpenSIPSControlFactory(self)
        socket_path = process.runtime.file(DispatcherConfig.socket_path)
        unlink(socket_path)
        self.opensips_listener = reactor.listenUNIX(socket_path, self.opensips_factory)
        self.opensips_management = opensips.ManagementInterface()
        self.management_factory = ManagementControlFactory(self)
        management_addr, management_port = DispatcherConfig.listen_management
        if DispatcherConfig.management_use_tls:
            self.management_listener = listenTLS(reactor, management_port, self.management_factory, self.tls_context, interface=management_addr)
        else:
            self.management_listener = reactor.listenTCP( management_port, self.management_factory, interface=management_addr)

    def run(self):
        log.debug('Using {0.__class__.__name__}'.format(reactor))
        process.signals.add_handler(signal.SIGHUP, self._handle_signal)
        process.signals.add_handler(signal.SIGINT, self._handle_signal)
        process.signals.add_handler(signal.SIGTERM, self._handle_signal)
        process.signals.add_handler(signal.SIGUSR1, self._handle_signal)
        for accounting_module in self.accounting:
            accounting_module.start()
        reactor.run(installSignalHandlers=False)

    def stop(self):
        reactor.callFromThread(self._shutdown)

    def send_command(self, command):
        return maybeDeferred(self.relay_factory.send_command, command)

    def update_statistics(self, session, stats):
        session.logger.info('statistics: {}'.format(stats))
        if stats['start_time'] is not None:
            for accounting in self.accounting:
                try:
                    accounting.do_accounting(stats)
                except Exception as e:
                    log.exception('An unhandled error occurred while doing accounting: %s' % e)

    def _handle_signal(self, signum, frame):
        if signum == signal.SIGUSR1:
            # toggle debugging
            if log.level.current != log.level.DEBUG:
                log.level.current = log.level.DEBUG
                log.info('Switched logging level to DEBUG')
            else:
                log.info('Switched logging level to {}'.format(DispatcherConfig.log_level))
                log.level.current = DispatcherConfig.log_level
        else:
            # terminate program
            signal_map = {signal.SIGTERM: 'Terminated', signal.SIGINT: 'Interrupted', signal.SIGHUP: 'Hangup'}
            log.info(signal_map.get(signum, 'Received signal {}, exiting.'.format(signum)))
            self.stop()

    def _shutdown(self):
        defer = DeferredList([result for result in [self.opensips_listener.stopListening(), self.management_listener.stopListening(), self.relay_listener.stopListening()] if result is not None])
        defer.addCallback(lambda x: self.opensips_factory.shutdown())
        defer.addCallback(lambda x: self.management_factory.shutdown())
        defer.addCallback(lambda x: self.relay_factory.shutdown())
        defer.addCallback(lambda x: self._stop())

    def _stop(self):
        for act in self.accounting:
            act.stop()
        reactor.stop()
