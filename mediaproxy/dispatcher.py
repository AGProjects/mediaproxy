#
# Copyright (C) 2008 AG Projects
# Author: Ruud Klaver <ruud@ag-projects.com>
#

"""Implementation of the MediaProxy relay component"""


import random
import cjson

from twisted.protocols.basic import LineOnlyReceiver
from twisted.internet.protocol import Factory
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


configuration = ConfigFile(configuration_filename)
configuration.read_settings("Dispatcher", Config)

class OpenSERControlProtocol(LineOnlyReceiver):

    def __init__(self):
        self.line_buf = []

    def lineReceived(self, line):
        if line.strip() == "" and self.line_buf:
            self.factory.dispatcher.send_command(self.line_buf[0], self.line_buf[1:])
            self.line_buf = []
        else:
            self.line_buf.append(line)


class OpenSERControlFactory(Factory):
    protocol = OpenSERControlProtocol

    def __init__(self, dispatcher):
        self.dispatcher = dispatcher
        self.prot = None

    def buildProtocol(self, addr):
        self.prot = Factory.buildProtocol(self, addr)
        return self.prot

    def reply(self, reply):
        if self.prot:
            self.prot.transport.write(reply + "\r\n")


class RelayServerProtocol(LineOnlyReceiver):

    def __init__(self):
        self.command_sent = None
        self.replied = True

    def send_command(self, command, headers):
        self.replied = False
        self.command_sent = command
        self.transport.write("\r\n".join([command] + headers + ["", ""]))

    def lineReceived(self, line):
        if self.replied:
            return
        self.replied = True
        line_split = line.split(" ", 1)[0]
        if line_split[0] == "expired":
            try:
                stats = cjson.decode(line_split[1])
            except cjson.DecodeError:
                log.error("Error decoding JSON from relay")
            else:
                self.factory.dispatcher.update_statistics(stats)
        if self.command_sent == "remove":
            try:
                stats = cjson.decode(line)
            except cjson.DecodeError:
                log.error("Error decoding JSON from relay")
                self.factory.dispatcher.openser.reply("error")
            else:
                self.factory.dispatcher.update_statistics(stats)
                self.factory.dispatcher.openser.reply("removed")
        else: # update command
            self.factory.dispatcher.openser.reply(line)

    def connectionLost(self, reason):
        log.debug("Relay from %s disconnected" % self.transport.getPeer().host)
        if not self.replied:
            self.factory.dispatcher.openser.reply("error")
        self.factory.protocols.remove(self)

class RelayFactory(Factory):
    protocol = RelayServerProtocol

    def __init__(self, dispatcher):
        self.dispatcher = dispatcher
        self.protocols = []

    def buildProtocol(self, addr):
        log.debug("Relay from %s connected" % addr.host)
        prot = Factory.buildProtocol(self, addr)
        self.protocols.append(prot)
        return prot

    def send_command(self, command, headers):
        if self.protocols:
            random.choice(self.protocols).send_command(command, headers)
        else:
            log.error("Could not send command, no relay has connected yet")
            self.dispatcher.openser.reply("error")


class Dispatcher(object):

    def __init__(self):
        self.cred = X509Credentials(Config.certificate, Config.private_key, [Config.ca])
        self.cred.verify_peer = True
        self.relay_factory = RelayFactory(self)
        reactor.listenTLS(Config.port, self.relay_factory, self.cred)
        self.openser = OpenSERControlFactory(self)
        reactor.listenUNIX(Config.socket, self.openser)

    def run(self):
        reactor.run()

    def send_command(self, command, headers):
        self.relay_factory.send_command(command, headers)

    def update_statistics(self, stats):
        log.debug("Got the following statistics: %s" % stats)
