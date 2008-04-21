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

from mediaproxy import configuration_filename
from mediaproxy.tls import Certificate, PrivateKey

class Config(ConfigSection):
    _datatypes = {"certificate": Certificate, "private_key": PrivateKey, "ca": Certificate}
    socket = "/var/run/proxydispatcher.sock"
    certificate = None
    private_key = None
    ca = None
    port = 12345
    relay_timeout = 5


configuration = ConfigFile(configuration_filename)
configuration.read_settings("Dispatcher", Config)

class OpenSERControlProtocol(LineOnlyReceiver):

    def __init__(self):
        self.line_buf = []

    def lineReceived(self, line):
        if line.strip() == "" and self.line_buf:
            defer = self.factory.dispatcher.send_command(self.line_buf[0], self.line_buf[1:])
            defer.addCallback(self.reply)
            defer.addErrback(self._relay_error)
            defer.addErrback(self._catch_all)
            self.line_buf = []
        else:
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
    protocol = OpenSERControlProtocol

    def __init__(self, dispatcher):
        self.dispatcher = dispatcher


class RelayError(Exception):
    pass


class RelayServerProtocol(LineOnlyReceiver):

    def __init__(self):
        self.command_sent = None
        self.defer = None
        self.timer = None
    
    def send_command(self, command, headers):
        log.debug('Issuing "%s" command to relay at %s' % (command, self.ip))
        self.defer = Deferred()
        self.timer = reactor.callLater(Config.relay_timeout, self.defer.errback, RelayError("Relay at %s timed out" % self.ip))
        self.defer.addBoth(self._defer_cleanup)
        self.command_sent = command
        self.transport.write("\r\n".join([command] + headers + ["", ""]))
        return self.defer

    def _defer_cleanup(self, result):
        if self.timer.active():
            self.timer.cancel()
        self.timer = None
        self.defer = None
        return result

    def lineReceived(self, line):
        line_split = line.split(" ", 1)
        if line_split[0] == "expired":
            try:
                stats = cjson.decode(line_split[1])
            except cjson.DecodeError:
                log.error("Error decoding JSON from relay at %s" % self.ip)
            else:
                self.factory.dispatcher.update_statistics(stats)
                del self.factory.sessions[stats["call_id"]]
            return
        if self.defer is None:
            log.error("Got unexpected response from relay at %s: %s" % (self.ip, line))
            return
        if line_split[0] == "error":
            self.defer.errback(RelayError('Received error from relay at %s in response to "%s" command' % (self.ip, self.command_sent)))
        elif self.command_sent == "remove":
            try:
                stats = cjson.decode(line)
            except cjson.DecodeError:
                log.error("Error decoding JSON from relay at %s" % self.ip)
            else:
                self.factory.dispatcher.update_statistics(stats)
                del self.factory.sessions[stats["call_id"]]
            self.defer.callback("removed")
        else: # update command
            self.defer.callback(line)

    def connectionLost(self, reason):
        log.debug("Relay at %s disconnected" % self.ip)
        self.factory.protocols.remove(self)
        if self.defer is not None:
            self.defer.errback(RelayError("Relay at %s disconnected" % self.ip))


class RelayFactory(Factory):
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
        else:
            try_relays = self.protocols[:]
            random.shuffle(try_relays)
            defer = self._try_next(try_relays, command, headers)
            defer.addCallback(self._add_session, try_relays, call_id)
            return defer

    def _add_session(self, result, try_relays, call_id):
        self.sessions[call_id] = try_relays[-1]
        return result

    def _relay_error(self, failure, try_relays, command, headers):
        failure.trap(RelayError)
        log.warn("Relay from %s returned error: %s" % (try_relays.pop().ip, failure.value))
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
        self.openser = OpenSERControlFactory(self)
        reactor.listenUNIX(Config.socket, self.openser)
        self.defer = None

    def run(self):
        reactor.run()

    def send_command(self, command, headers):
        return maybeDeferred(self.relay_factory.send_command, command, headers)

    def update_statistics(self, stats):
        log.debug("Got the following statistics: %s" % stats)
