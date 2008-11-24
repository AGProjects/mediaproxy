# Copyright (C) 2008 AG Projects
# Author: Ruud Klaver <ruud@ag-projects.com>
#

"""Implementation of the MediaProxy dispatcher"""


import random
import signal
import cPickle as pickle
import cjson

for name in ('epollreactor', 'kqreactor', 'pollreactor', 'selectreactor'):
    try:    __import__('twisted.internet.%s' % name, globals(), locals(), fromlist=[name]).install()
    except: continue
    else:   break
from twisted.protocols.basic import LineOnlyReceiver
from twisted.internet.error import ConnectionDone
from twisted.internet.protocol import Factory
from twisted.internet.defer import Deferred, DeferredList, maybeDeferred, succeed
from twisted.internet import reactor

from gnutls.errors import CertificateSecurityError

from application import log
from application.process import process
from application.configuration import *
from application.system import unlink

from mediaproxy import configuration_filename, default_dispatcher_port, default_management_port
from mediaproxy.tls import X509Credentials, X509NameValidator
from mediaproxy.interfaces import opensips


log.msg("Twisted is using %s" % reactor.__module__.rsplit('.', 1)[-1])


class DispatcherAddress(datatypes.NetworkAddress):
    _defaultPort = default_dispatcher_port

class DispatcherManagementAddress(datatypes.NetworkAddress):
    _defaultPort = default_management_port

class AccountingModuleList(datatypes.StringList):
    _valid_backends = set(('database', 'radius'))
    
    def __new__(cls, value):
        proposed_backends = set(datatypes.StringList.__new__(cls, value))
        invalid_names = proposed_backends - cls._valid_backends
        for name in invalid_names:
            log.warn("Ignoring invalid accounting module name: `%s'" % name)
        return list(proposed_backends & cls._valid_backends)


class Config(ConfigSection):
    _datatypes = {'listen': DispatcherAddress, 'listen_management': DispatcherManagementAddress, 'management_use_tls': datatypes.Boolean,
                  'accounting': AccountingModuleList, 'passport': X509NameValidator, 'management_passport': X509NameValidator}
    socket_path = "dispatcher.sock"
    listen = DispatcherAddress("any")
    listen_management = DispatcherManagementAddress("any")
    relay_timeout = 5
    cleanup_timeout = 3600
    management_use_tls = True
    accounting = []
    passport = None
    management_passport = None


configuration = ConfigFile(configuration_filename)
configuration.read_settings("Dispatcher", Config)

class ControlProtocol(LineOnlyReceiver):
    noisy = False

    def __init__(self):
        self.in_progress = 0

    def lineReceived(self, line):
        raise NotImplementedError()

    def connectionLost(self, reason):
        log.debug("Connection to %s lost: %s" % (self.description, reason.value))
        self.factory.connection_lost(self)

    def reply(self, reply):
        self.transport.write(reply + "\r\n")

    def _relay_error(self, failure):
        failure.trap(RelayError)
        log.error("Error processing request: %s" % failure.value)
        self.transport.write("error\r\n")

    def _catch_all(self, failure):
        log.error(failure.getBriefTraceback())
        self.transport.write("error\r\n")

    def _decrement(self, result):
        self.in_progress = 0
        if self.factory.shutting_down:
            self.transport.loseConnection()

    def _add_callbacks(self, defer):
        defer.addCallback(self.reply)
        defer.addErrback(self._relay_error)
        defer.addErrback(self._catch_all)
        defer.addBoth(self._decrement)


class OpenSIPSControlProtocol(ControlProtocol):
    description = "OpenSIPS"

    def __init__(self):
        self.line_buf = []
        ControlProtocol.__init__(self)

    def lineReceived(self, line):
        if line == "":
            if self.line_buf:
                self.in_progress += 1
                defer = self.factory.dispatcher.send_command(self.line_buf[0], self.line_buf[1:])
                self._add_callbacks(defer)
                self.line_buf = []
        elif not line.endswith(": "):
            self.line_buf.append(line)


class ManagementControlProtocol(ControlProtocol):
    description = "Management interface client"

    def connectionMade(self):
        if Config.management_use_tls and Config.management_passport is not None:
            peer_cert = self.transport.getPeerCertificate()
            if not Config.management_passport.accept(peer_cert):
                self.transport.loseConnection(CertificateSecurityError('peer certificate not accepted'))
                return

    def lineReceived(self, line):
        if line in ["quit", "exit"]:
            self.transport.loseConnection()
        elif line == "summary":
            defer = self.factory.dispatcher.relay_factory.get_summary()
            self._add_callbacks(defer)
        elif line == "sessions":
            defer = self.factory.dispatcher.relay_factory.get_statistics()
            self._add_callbacks(defer)
        else:
            log.error("Unknown command on management interface: %s" % line)
            self.reply("error")


class ControlFactory(Factory):
    noisy = False

    def __init__(self, dispatcher):
        self.dispatcher = dispatcher
        self.protocols = []
        self.shutting_down = False

    def buildProtocol(self, addr):
        prot = Factory.buildProtocol(self, addr)
        self.protocols.append(prot)
        return prot

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


class RelayServerProtocol(LineOnlyReceiver):
    noisy = False
    MAX_LENGTH = 1024 * 1024

    def __init__(self):
        self.commands = {}
        self.ready = True
        self.sequence_number = 0
    
    def send_command(self, command, headers):
        log.debug('Issuing "%s" command to relay at %s' % (command, self.ip))
        seq = str(self.sequence_number)
        self.sequence_number += 1
        defer = Deferred()
        timer = reactor.callLater(Config.relay_timeout, self._timeout, seq, defer)
        self.commands[seq] = (command, defer, timer)
        self.transport.write("\r\n".join([" ".join([command, seq])] + headers + ["", ""]))
        return defer

    def _timeout(self, seq, defer):
        del self.commands[seq]
        defer.errback(RelayError("Relay at %s timed out" % self.ip))

    def connectionMade(self):
        if Config.passport is not None:
            peer_cert = self.transport.getPeerCertificate()
            if not Config.passport.accept(peer_cert):
                self.transport.loseConnection(CertificateSecurityError('peer certificate not accepted'))
                return
        self.factory.purge_sessions(self)

    def lineReceived(self, line):
        try:
            first, rest = line.split(" ", 1)
        except ValueError:
            log.error("Could not decode reply from relay %s: %s" % (self.ip, line))
            return
        if first == "expired":
            try:
                stats = cjson.decode(rest)
            except cjson.DecodeError:
                log.error("Error decoding JSON from relay at %s" % self.ip)
            else:
                session = self.factory.sessions[stats["call_id"]]
                if session.dialog_id is not None:
                    if stats["to_tag"] is not None:
                        self.factory.dispatcher.opensips_management.end_dialog(session.dialog_id)
                    stats["dialog_id"] = session.dialog_id
                stats["timed_out"] = True
                self.factory.dispatcher.update_statistics(stats)
                del self.factory.sessions[stats["call_id"]]
            return
        try:
            command, defer, timer = self.commands.pop(first)
        except KeyError:
            log.error("Got unexpected response from relay at %s: %s" % (self.ip, line))
            return
        timer.cancel()
        if rest == "error":
            defer.errback(RelayError('Received error from relay at %s in response to "%s" command' % (self.ip, command)))
        elif rest == "halting":
            self.ready = False
            defer.errback(RelayError("Relay at %s is shutting down" % self.ip))
        elif command == "remove":
            try:
                stats = cjson.decode(rest)
            except cjson.DecodeError:
                log.error("Error decoding JSON from relay at %s" % self.ip)
            else:
                stats["timed_out"] = False
                self.factory.dispatcher.update_statistics(stats)
                del self.factory.sessions[stats["call_id"]]
            defer.callback("removed")
        else: # update command
            defer.callback(rest)

    def connectionLost(self, reason):
        if reason.type != ConnectionDone:
            log.error("Connection with relay at %s was lost: %s" % (self.ip, reason.value))
        else:
            log.msg("Connection with relay at %s was closed" % self.ip)
        for command, defer, timer in self.commands.itervalues():
            timer.cancel()
            defer.errback(RelayError("Relay at %s disconnected" % self.ip))
        self.factory.connection_lost(self.ip)


class DialogID(str):
    def __new__(cls, did):
        if did is None:
            return None
        try:
            h_entry, h_id = did.split(':')
        except:
            log.error("invalid dialog_id value: `%s'" % did)
            return None
        instance = str.__new__(cls, did)
        instance.h_entry = h_entry
        instance.h_id = h_id
        return instance


class RelaySession(object):
    def __init__(self, relay_ip, command_headers):
        self.relay_ip = relay_ip
        self.dialog_id = DialogID(command_headers.get('dialog_id'))


class RelayFactory(Factory):
    noisy = False
    protocol = RelayServerProtocol

    def __init__(self, dispatcher):
        self.dispatcher = dispatcher
        self.relays = {}
        self.shutting_down = False
        state_file = process.runtime_file("dispatcher_state")
        try:
            self.sessions = pickle.load(open(state_file))
        except:
            self.sessions = {}
            self.cleanup_timers = {}
        else:
            self.cleanup_timers = dict((ip, reactor.callLater(Config.cleanup_timeout, self._do_cleanup, ip)) for ip in set(session.relay_ip for session in self.sessions.itervalues()))
        unlink(state_file)

    def buildProtocol(self, addr):
        ip = addr.host
        log.debug("Connection from relay at %s" % ip)
        if ip in self.relays:
            log.error("Connection to relay %s is already present, disconnecting" % ip)
            return None
        if ip in self.cleanup_timers:
            timer = self.cleanup_timers.pop(ip)
            timer.cancel()
        prot = Factory.buildProtocol(self, addr)
        prot.ip = ip
        self.relays[ip] = prot
        return prot

    def purge_sessions(self, relay):
        defer = relay.send_command("sessions", [])
        defer.addCallback(self._cb_purge_sessions, relay.ip)

    def _cb_purge_sessions(self, result, relay_ip):
        relay_sessions = cjson.decode(result)
        relay_call_ids = [session["call_id"] for session in relay_sessions]
        for session_id, session in self.sessions.items():
            if session.relay_ip == relay_ip and session_id not in relay_call_ids:
                log.warn("Session %s is not longer on relay %s, statistics are probably lost" % (session_id, relay_ip))
                del self.sessions[session_id]

    def send_command(self, command, headers):
        try:
            parsed_headers = dict(header.split(": ", 1) for header in headers)
        except:
            raise RelayError("Could not parse headers from OpenSIPs")
        try:
            call_id = parsed_headers["call_id"]
        except KeyError:
            raise RelayError("Missing call_id header")
        if call_id in self.sessions:
            relay = self.sessions[call_id].relay_ip
            if relay not in self.relays:
                raise RelayError("Relay for this session (%s) is no longer connected" % relay)
            return self.relays[relay].send_command(command, headers)
        elif command == "update":
            preferred_relay = parsed_headers.get("media_relay")
            if preferred_relay is not None:
                try_relays = [protocol for protocol in self.relays.itervalues() if protocol.ip == preferred_relay]
                other_relays = [protocol for protocol in self.relays.itervalues() if protocol.ready and protocol.ip != preferred_relay]
                random.shuffle(other_relays)
                try_relays.extend(other_relays)
            else:
                try_relays = [protocol for protocol in self.relays.itervalues() if protocol.ready]
                random.shuffle(try_relays)
            defer = self._try_next(try_relays, command, headers)
            defer.addCallback(self._add_session, try_relays, call_id, parsed_headers)
            return defer
        else:
            raise RelayError("Non-update command received from OpenSIPS for unknown session")

    def _add_session(self, result, try_relays, call_id, parsed_headers):
        self.sessions[call_id] = RelaySession(try_relays[-1].ip, parsed_headers)
        return result

    def _relay_error(self, failure, try_relays, command, headers):
        failure.trap(RelayError)
        failed_relay = try_relays.pop()
        log.warn("Relay from %s:%d returned error: %s" % (failed_relay.ip, failure.value))
        return self._try_next(try_relays, command, headers)

    def _try_next(self, try_relays, command, headers):
        if len(try_relays) == 0:
            raise RelayError("No suitable relay found")
        defer = try_relays[-1].send_command(command, headers)
        defer.addErrback(self._relay_error, try_relays, command, headers)
        return defer

    def get_summary(self):
        defer = DeferredList([relay.send_command("summary", []).addCallback(self._got_summary, ip).addErrback(self._summary_error, ip) for ip, relay in self.relays.iteritems()])
        defer.addCallback(self._got_summaries)
        return defer

    def _got_summary(self, summary, ip):
        summary = cjson.decode(summary)
        summary["ip"] = ip
        return summary

    def _summary_error(self, failure, ip):
        log.error("Error processing query at relay %s: %s" % (ip, failure.value))
        return dict(status="error", ip=ip)

    def _got_summaries(self, results):
        return "\r\n".join([cjson.encode(result) for succeeded, result in results if succeeded] + [''])

    def get_statistics(self):
        defer = DeferredList([relay.send_command("sessions", []).addCallback(lambda stats: cjson.decode(stats)) for relay in self.relays.itervalues()])
        defer.addCallback(self._got_statistics)
        return defer

    def _got_statistics(self, results):
        return "\r\n".join([cjson.encode(session) for session in sum([stats for succeeded, stats in results if succeeded], [])] + [''])

    def connection_lost(self, ip):
        del self.relays[ip]
        if self.shutting_down:
            if len(self.relays) == 0:
                self.defer.callback(None)
        else:
            self.cleanup_timers[ip] = reactor.callLater(Config.cleanup_timeout, self._do_cleanup, ip)

    def _do_cleanup(self, ip):
        log.debug("Doing cleanup for old relay %s" % ip)
        del self.cleanup_timers[ip]
        for call_id in [call_id for call_id, session in self.sessions.items() if session.relay_ip == ip]:
            del self.sessions[call_id]

    def shutdown(self):
        if self.shutting_down:
            return
        self.shutting_down = True
        for timer in self.cleanup_timers.itervalues():
            timer.cancel()
        if len(self.relays) == 0:
            retval = succeed(None)
        else:
            for prot in self.relays.itervalues():
                prot.transport.loseConnection()
            self.defer = Deferred()
            retval = self.defer
        retval.addCallback(self._save_state)
        return retval

    def _save_state(self, result):
        pickle.dump(self.sessions, open(process.runtime_file("dispatcher_state"), "w"))


class Dispatcher(object):

    def __init__(self):
        self.accounting = [__import__("mediaproxy.interfaces.accounting.%s" % mod.lower(), globals(), locals(), [""]).Accounting() for mod in set(Config.accounting)]
        self.cred = X509Credentials(cert_name='dispatcher')
        self.relay_factory = RelayFactory(self)
        dispatcher_addr, dispatcher_port = Config.listen
        self.relay_listener = reactor.listenTLS(dispatcher_port, self.relay_factory, self.cred, interface=dispatcher_addr)
        self.opensips_factory = OpenSIPSControlFactory(self)
        socket_path = process.runtime_file(Config.socket_path)
        unlink(socket_path)
        self.opensips_listener = reactor.listenUNIX(socket_path, self.opensips_factory)
        self.opensips_management = opensips.ManagementInterface()
        self.management_factory = ManagementControlFactory(self)
        management_addr, management_port = Config.listen_management
        if Config.management_use_tls:
            self.management_listener = reactor.listenTLS(management_port, self.management_factory, self.cred, interface=management_addr)
        else:
            self.management_listener = reactor.listenTCP(management_port, self.management_factory, interface=management_addr)

    def run(self):
        process.signals.add_handler(signal.SIGHUP, self._handle_SIGHUP)
        process.signals.add_handler(signal.SIGINT, self._handle_SIGINT)
        process.signals.add_handler(signal.SIGTERM, self._handle_SIGTERM)
        for accounting_module in self.accounting:
            accounting_module.start()
        reactor.run(installSignalHandlers=False)

    def send_command(self, command, headers):
        return maybeDeferred(self.relay_factory.send_command, command, headers)

    def update_statistics(self, stats):
        log.debug("Got statistics: %s" % stats)
        if stats["to_tag"] is not None:
            for act in self.accounting:
                act.do_accounting(stats)

    def _handle_SIGHUP(self, *args):
        log.msg("Received SIGHUP, shutting down.")
        reactor.callFromThread(self._shutdown)

    def _handle_SIGINT(self, *args):
        if process._daemon:
            log.msg("Received SIGINT, shutting down.")
        else:
            log.msg("Received KeyboardInterrupt, exiting.")
        reactor.callFromThread(self._shutdown)

    def _handle_SIGTERM(self, *args):
        log.msg("Received SIGTERM, shutting down.")
        reactor.callFromThread(self._shutdown)

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
