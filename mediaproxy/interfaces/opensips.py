# Copyright (C) 2006-2008 AG Projects.
#

"""The OpenSIPS Management Interface"""


import re
import socket
from collections import deque
from twisted.internet import reactor, defer
from twisted.internet.protocol import DatagramProtocol
from twisted.internet.error import CannotListenError
from twisted.python.failure import Failure
from application.configuration import ConfigSection, ConfigFile
from application.python.util import Singleton
from application.process import process
from application.system import unlink
from application import log

from mediaproxy import configuration_filename


class OpenSIPSConfig(ConfigSection):
    socket_path = '/var/run/opensips/socket'
    max_connections = 10

config_file = ConfigFile(configuration_filename)
config_file.read_settings('OpenSIPS', OpenSIPSConfig)


class Error(Exception): pass
class CommandError(Error): pass
class TimeoutError(Error): pass
class NegativeReplyError(Error): pass


class Request(object):
    def __init__(self, command):
        self.command = command
        self.deferred = defer.Deferred()


class UNIXSocketProtocol(DatagramProtocol):
    noisy = False

    def datagramReceived(self, data, address):
        deferred = self.transport.deferred
        if deferred is None or deferred.called:
            return
        # accumulate in a buffer until message end (do this later when implemented by opensips) -Dan
        if not data:
            failure = Failure(CommandError("Empty reply from OpenSIPS"))
            deferred.errback(failure)
            return
        try:
            status, msg = data.split('\n', 1)
        except ValueError:
            failure = Failure(CommandError("Missing line terminator after status line in OpenSIPS reply"))
            deferred.errback(failure)
            return
        if status.upper() == '200 OK':
            deferred.callback(msg)
        else:
            deferred.errback(Failure(NegativeReplyError(status)))


class UNIXSocketConnection(object):
    timeout = 3

    def __init__(self, socket_path):
        self._initialized = False
        self.path = socket_path
        self.transport = reactor.listenUNIXDatagram(self.path, UNIXSocketProtocol())
        reactor.addSystemEventTrigger('during', 'shutdown', self.close)
        self.transport.deferred = None ## placeholder for the deferred used by a request
        self._initialized = True

    def close(self):
        if self._initialized:
            self.transport.stopListening()
            unlink(self.path)

    def _get_deferred(self):
        return self.transport.deferred
    def _set_deferred(self, d):
        self.transport.deferred = d
    deferred = property(_get_deferred, _set_deferred)

    def _did_timeout(self, deferred):
        if deferred.called:
            return
        deferred.errback(Failure(TimeoutError("OpenSIPS command did timeout")))
    
    def send(self, request):
        self.deferred = request.deferred
        try:
            self.transport.write(request.command, OpenSIPSConfig.socket_path)
        except socket.error, why:
            log.error("cannot write request to %s: %s" % (OpenSIPSConfig.socket_path, why[1]))
            self.deferred.errback(Failure(CommandError("Cannot send request to OpenSIPS")))
        else:
            reactor.callLater(self.timeout, self._did_timeout, self.deferred)


class UNIXSocketConnectionPool(object):
    """Pool of UNIX socket connection to OpenSIPS"""

    def __init__(self, max_connections=10, pool_id=''):
        assert max_connections > 0, 'maximum should be > 0'
        self.max = max_connections
        self.id = pool_id
        self.workers = 0
        self.waiters = deque()
        self.connections = deque()

    def _create_connections_as_needed(self):
        while self.workers < self.max and len(self.waiters) > len(self.connections):
            socket_name = "opensips_%s%02d.sock" % (self.id, self.workers+1)
            socket_path = process.runtime_file(socket_name)
            unlink(socket_path)
            try:
                conn = UNIXSocketConnection(socket_path)
            except CannotListenError, why:
                log.error("cannot create an OpenSIPS UNIX socket connection: %s" % str(why))
                break
            self.connections.append(conn)
            self.workers += 1
    
    def _release_connection(self, result, conn):
        self.connections.append(conn)
        self._process_waiters()
        return result
    
    def _process_waiters(self):
        while self.waiters:
            try:
                conn = self.connections.popleft()
            except IndexError:
                return
            request = self.waiters.popleft()
            request.deferred.addBoth(self._release_connection, conn)
            conn.send(request)
    
    def defer_to_connection(self, command):
        request = Request(command)
        self.waiters.append(request)
        self._create_connections_as_needed()
        self._process_waiters()
        return request.deferred


class ManagementInterface(object):
    __metaclass__ = Singleton
    
    def __init__(self):
        self.pool = UNIXSocketConnectionPool(OpenSIPSConfig.max_connections)
    
    def __RH_make_bool(self, result):
        if isinstance(result, Failure):
            return False
        return True
    
    def __RH_end_dialog(self, result):
        if isinstance(result, Failure):
            log.error("failed to end dialog: %s: %s" % (result.type, str(result.value)))
            return False
        return True
    
    def end_dialog(self, dialog_id):
        cmd = ':dlg_end_dlg:\n%s\n%s\n\n' % (dialog_id.h_entry, dialog_id.h_id)
        return self.pool.defer_to_connection(cmd).addBoth(self.__RH_end_dialog)

