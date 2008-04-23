#
# Copyright (C) 2008 AG Projects
# Author: Ruud Klaver <ruud@ag-projects.com>
#

"""Implementation of the MediaProxy relay component"""


import random
import cjson

from twisted.protocols.basic import LineOnlyReceiver
from twisted.internet.protocol import Factory
from twisted.internet.defer import Deferred, maybeDeferred
from twisted.internet import epollreactor
epollreactor.install()
from twisted.internet import reactor

from gnutls.interfaces.twisted import X509Credentials

from application import log
from application.configuration import *

from mediaproxy import configuration_filename, default_dispatcher_port
from mediaproxy.tls import Certificate, PrivateKey

class Config(ConfigSection):
    _datatypes = {"certificate": Certificate, "private_key": PrivateKey, "ca": Certificate}
    socket = "/var/run/mediaproxy/dispatcher.sock"
    certificate = None
    private_key = None
    ca = None
    port = default_dispatcher_port
    relay_timeout = 5


configuration = ConfigFile(configuration_filename)
configuration.read_settings("Dispatcher", Config)

class OpenSERControlProtocol(LineOnlyReceiver):
    noisy = False

    def __init__(self):
        self.line_buf = []

    def lineReceived(self, line):
        if line.strip() == "" and self.line_buf:
            defer = self.factory.dispatcher.send_command(self.line_buf[0], self.line_buf[1:])
            defer.addCallback(self.reply)
            defer.addErrback(self._relay_error)
            defer.addErrback(self._catch_all)
            self.line_buf = []
        elif not line.endswith(": "):
            self.line_buf.append(line)

    def connectionLost(self, reason):
        log.debug("Connection to OpenSER lost: %s" % reason.value)

    def reply(self, reply):
        self.transport.write(reply + "\r\n")

    def _relay_error(self, failure):
        failure.trap(RelayError)
        log.error("Error processing request: %s" % failure.value)
        self.transport.write("error\r\n")

    def _catch_all(self, failure):
        log.error(failure.getBriefTraceback())
        self.transport.write("error\r\n")


class OpenSERControlFactory(Factory):
    noisy = False
    protocol = OpenSERControlProtocol

    def __init__(self, dispatcher):
        self.dispatcher = dispatcher


class RelayError(Exception):
    pass


class RelayServerProtocol(LineOnlyReceiver):
    noisy = False

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

    def lineReceived(self, line):
        try:
            first, rest = line.split(" ", 1)
        except ValueError:
            error.log("Could not decode reply from relay: %s" % line)
            return
        if first == "expired":
            try:
                stats = cjson.decode(rest)
            except cjson.DecodeError:
                log.error("Error decoding JSON from relay at %s" % self.ip)
            else:
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
                self.factory.dispatcher.update_statistics(stats)
                del self.factory.sessions[stats["call_id"]]
            defer.callback("removed")
        else: # update command
            defer.callback(rest)

    def connectionLost(self, reason):
        log.debug("Relay at %s disconnected" % self.ip)
        self.factory.protocols.remove(self)
        for command, defer, timer in self.commands.itervalues():
            timer.cancel()
            defer.errback(RelayError("Relay at %s disconnected" % self.ip))


class RelayFactory(Factory):
    noisy = False
    protocol = RelayServerProtocol

    def __init__(self, dispatcher):
        self.dispatcher = dispatcher
        self.protocols = []
        self.sessions = {}

    def buildProtocol(self, addr):
        log.debug("Relay at %s connected" % addr.host)
        prot = Factory.buildProtocol(self, addr)
        prot.ip = addr.host
        self.protocols.append(prot)
        return prot

    def send_command(self, command, headers):
        call_id = None
        for header in headers:
            if header.startswith("call_id: "):
                call_id = header.split("call_id: ", 1)[1]
                break
        if call_id is None:
            raise RelayError("Could not parse call_id")
        if call_id in self.sessions:
            relay = self.sessions[call_id]
            if relay not in self.protocols:
                raise RelayError("Relay for this session is no longer connected")
            return self.sessions[call_id].send_command(command, headers)
        elif command == "update":
            preferred_relay = None
            for header in headers:
                if header.startswith("media_relay: "):
                    preferred_relay = header.split("media_relay: ", 1)[1]
                    break
            if preferred_relay is None:
                try_relays = [protocol for protocol in self.protocols if protocol.ready]
                random.shuffle(try_relays)
            else:
                try_relays = [protocol for protocol in self.protocols if protocol.ip == preferred_relay]
            defer = self._try_next(try_relays, command, headers)
            defer.addCallback(self._add_session, try_relays, call_id)
            return defer
        else:
            raise RelayError("Non-update command received from OpenSER for unknown session")

    def _add_session(self, result, try_relays, call_id):
        self.sessions[call_id] = try_relays[-1]
        return result

    def _relay_error(self, failure, try_relays, command, headers):
        failure.trap(RelayError)
        failed_relay = try_relays.pop()
        log.warn("Relay from %s returned error: %s" % (failed_relay.ip, failure.value))
        return self._try_next(try_relays, command, headers)

    def _try_next(self, try_relays, command, headers):
        if len(try_relays) == 0:
            raise RelayError("No suitable relay found")
        defer = try_relays[-1].send_command(command, headers)
        defer.addErrback(self._relay_error, try_relays, command, headers)
        return defer


class Dispatcher(object):

    def __init__(self):
        self.cred = X509Credentials(Config.certificate, Config.private_key, [Config.ca])
        self.cred.verify_peer = True
        self.relay_factory = RelayFactory(self)
        reactor.listenTLS(Config.port, self.relay_factory, self.cred)
        self.openser_factory = OpenSERControlFactory(self)
        reactor.listenUNIX(Config.socket, self.openser_factory)

    def run(self):
        reactor.run()

    def send_command(self, command, headers):
        return maybeDeferred(self.relay_factory.send_command, command, headers)

    def update_statistics(self, stats):
        log.debug("Got the following statistics: %s" % stats)
