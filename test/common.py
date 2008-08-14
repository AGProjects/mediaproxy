# Copyright (C) 2008 AG Projects
#

import sys
sys.path.append(".")
sys.path.append("..")
import os
import random
import string

import mediaproxy

from application.system import default_host_ip
from application.configuration import *
from application.process import process
process._system_config_directory = mediaproxy.system_config_directory

from twisted.internet.protocol import DatagramProtocol, ClientFactory
from twisted.protocols.basic import LineOnlyReceiver
from twisted.internet.task import LoopingCall
from twisted.internet.defer import Deferred, DeferredList, succeed
from twisted.internet import reactor

from mediaproxy.headers import EncodingDict

class Config(ConfigSection):
    socket = "/var/run/mediaproxy/dispatcher.sock"

configuration = ConfigFile(mediaproxy.configuration_filename)
configuration.read_settings("Dispatcher", Config)


random_data = os.urandom(512)


class OpenSERControlClientProtocol(LineOnlyReceiver):

    def __init__(self):
        self.defer = None

    def lineReceived(self, line):
        if line == "error":
            print "got error from dispatcher!"
            reactor.stop()
        elif self.defer is not None:
            print "got ip/ports from dispatcher: %s" % line
            ip, ports = line.split(" ", 1)
            defer = self.defer
            self.defer = None
            defer.callback((ip, [int(i) for i in ports.split()]))
        else:
            print "got reply from dispatcher: %s" % line
            defer = self.defer
            self.defer = None
            defer.callback(line)

    def _send_command(self, command, headers):
        self.defer = Deferred()
        data = "\r\n".join([command] + ["%s: %s" % item for item in headers.iteritems()] + ["", ""])
        #print "writing on socket:\n%s" % data
        self.transport.write(data)
        return self.defer

    def update(self, **kw_args):
        return self._send_command("update", EncodingDict(kw_args))

    def remove(self, **kw_args):
        return self._send_command("remove", EncodingDict(kw_args))


class OpenSERConnectorFactory(ClientFactory):
    protocol = OpenSERControlClientProtocol

    def __init__(self):
        self.defer = Deferred()

    def buildProtocol(self, addr):
        prot = ClientFactory.buildProtocol(self, addr)
        reactor.callLater(0, self.defer.callback, prot)
        return prot


class MediaReceiverProtocol(DatagramProtocol):

    def __init__(self, endpoint, index):
        self.endpoint = endpoint
        self.index = index
        self.loop = None
        self.received_media = False
        self.defer = Deferred()

    def datagramReceived(self, data, (host, port)):
        if not self.received_media:
            self.received_media = True
            print "received media %d for %s from %s:%d" % (self.index, self.endpoint.name, host, port)
            self.defer.callback(None)

    def connectionRefused(self):
        print "connection refused for media %d for %s" % (self.index, self.endpoint.name)


class Endpoint(object):

    def __init__(self, sip_uri, user_agent, is_caller):
        if is_caller:
            self.name = "caller"
        else:
            self.name = "callee"
        self.sip_uri = sip_uri
        self.user_agent = user_agent
        self.tag = "".join(random.sample(string.ascii_lowercase, 8))
        self.connectors = []
        self.media = []
        self.cseq = 1

    def set_media(self, media):
        assert(len(self.connectors) == 0)
        self.media = media
        for index, (media_type, port, direction) in enumerate(self.media):
            if port != 0:
                protocol = MediaReceiverProtocol(self, index)
                connector = reactor.listenUDP(port, protocol)
            else:
                connector = None
            self.connectors.append(connector)
        return DeferredList([connector.protocol.defer for connector in self.connectors if connector is not None])

    def get_media(self, use_old_hold):
        if use_old_hold:
            ip = "0.0.0.0"
        else:
            ip = default_host_ip
        return [(media_type, ip, port, direction) for media_type, port, direction in self.media]

    def start_media(self, ip, ports):
        for port, connector in zip(ports, self.connectors):
            if connector is not None:
                protocol = connector.protocol
                protocol.transport.connect(ip, port)
                protocol.loop = LoopingCall(protocol.transport.write, random_data)
                protocol.loop.start(random.uniform(0.5, 1))

    def stop_media(self):
        defers = []
        for connector in self.connectors:
            if connector is not None:
                if connector.protocol.loop is not None:
                    connector.protocol.loop.stop()
                    connector.protocol.loop = None
                defer = connector.stopListening()
                if defer is not None:
                    defers.append(defer)
        self.connectors = []
        if defers:
            return DeferredList(defers)
        else:
            return succeed(None)


class Session(object):

    def __init__(self, caller, callee):
        self.caller = caller
        self.callee = callee
        self.call_id = "".join(random.sample(string.ascii_letters, 24))

    def _get_parties(self, party):
        party = getattr(self, party)
        if party is self.caller:
            other = self.callee
        else:
            other = self.caller
        return party, other

    def do_update(self, openser, party, type, is_final, use_old_hold=False):
        party, other = self._get_parties(party)
        if type == "request":
            from_tag = party.tag
            to_tag = other.tag
            from_uri = party.sip_uri
            to_uri = other.sip_uri
            cseq = party.cseq
        else:
            from_tag = other.tag
            to_tag = party.tag
            from_uri = other.sip_uri
            to_uri = party.sip_uri
            cseq = other.cseq
        if is_final:
            defer = openser.update(call_id = self.call_id, from_tag = from_tag, to_tag = to_tag, from_uri = from_uri, to_uri = to_uri, cseq = cseq,  user_agent = party.user_agent, media = party.get_media(use_old_hold), type = type)
        else:
            defer = openser.update(call_id = self.call_id, from_tag = from_tag, from_uri = from_uri, to_uri = to_uri, cseq = cseq,  user_agent = party.user_agent, media = party.get_media(use_old_hold), type = type)
        if is_final:
            if type == "request":
                party.cseq += 1
            else:
                other.cseq += 1
        return defer

    def do_remove(self, openser, party):
        party, other = self._get_parties(party)
        openser.remove(call_id = self.call_id, from_tag = party.tag, to_tag = other.tag)

def connect_to_dispatcher():
    factory = OpenSERConnectorFactory()
    connector = reactor.connectUNIX(Config.socket, factory)
    return connector, factory.defer
