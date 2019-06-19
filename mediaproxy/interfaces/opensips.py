
import json
import socket
import urlparse

from abc import ABCMeta, abstractmethod, abstractproperty
from application import log
from application.python.types import Singleton
from application.process import process
from application.system import unlink
from random import getrandbits
from twisted.internet import reactor, defer
from twisted.internet.protocol import DatagramProtocol
from twisted.python.failure import Failure

from mediaproxy.configuration import OpenSIPSConfig


class Error(Exception):
    pass


class TimeoutError(Error):
    pass


class OpenSIPSError(Error):
    pass


class NegativeReplyError(OpenSIPSError):
    def __init__(self, code, message):
        super(NegativeReplyError, self).__init__(code, message)
        self.code = code
        self.message = message

    def __repr__(self):
        return '{0.__class__.__name__}({0.code!r}, {0.message!r})'.format(self)

    def __str__(self):
        return '[{0.code}] {0.message}'.format(self)


class Request(object):
    __metaclass__ = ABCMeta

    method = abstractproperty()

    @abstractmethod
    def __init__(self, *args):
        self.id = '{:x}'.format(getrandbits(32))
        self.args = list(args)
        self.deferred = defer.Deferred()

    @property
    def __data__(self):
        return dict(jsonrpc='2.0', id=self.id, method=self.method, params=self.args)

    @abstractmethod
    def process_response(self, response):
        raise NotImplementedError


# noinspection PyAbstractClass
class BooleanRequest(Request):
    """A request that returns True if successful, False otherwise"""
    def process_response(self, response):
        return not isinstance(response, Failure)


class AddressReload(BooleanRequest):
    method = 'address_reload'

    def __init__(self):
        super(AddressReload, self).__init__()


class DomainReload(BooleanRequest):
    method = 'domain_reload'

    def __init__(self):
        super(DomainReload, self).__init__()


class EndDialog(BooleanRequest):
    method = 'dlg_end_dlg'

    def __init__(self, dialog_id):
        super(EndDialog, self).__init__(dialog_id)


class RefreshWatchers(BooleanRequest):
    method = 'refresh_watchers'

    def __init__(self, account, refresh_type):
        super(RefreshWatchers, self).__init__('sip:{}'.format(account), 'presence', refresh_type)


class UpdateSubscriptions(BooleanRequest):
    method = 'rls_update_subscriptions'

    def __init__(self, account):
        super(UpdateSubscriptions, self).__init__('sip:{}'.format(account))


class GetOnlineDevices(Request):
    method = 'ul_show_contact'

    def __init__(self, account):
        super(GetOnlineDevices, self).__init__(OpenSIPSConfig.location_table, account)

    def process_response(self, response):
        if isinstance(response, Failure):
            if response.type is NegativeReplyError and response.value.code == 404:
                return []
            return response
        return [ContactData(contact) for contact in response[u'Contacts']]


class ContactData(dict):
    __fields__ = {u'contact', u'expires', u'received', u'user_agent'}

    def __init__(self, data):
        super(ContactData, self).__init__({key: value for key, value in ((key.lower().replace(u'-', u'_'), value) for key, value in data.iteritems()) if key in self.__fields__})
        self.setdefault(u'user_agent', None)
        if u'received' in self:
            parsed_received = urlparse.parse_qs(self[u'received'])
            if u'target' in parsed_received:
                self[u'NAT_contact'] = parsed_received[u'target'][0]
            else:
                self[u'NAT_contact'] = self[u'received']
            del self[u'received']
        else:
            self[u'NAT_contact'] = self[u'contact']


class UNIXSocketProtocol(DatagramProtocol):
    noisy = False

    def datagramReceived(self, data, address):
        log.debug('Got MI response: {}'.format(data))
        try:
            response = json.loads(data)
        except ValueError:
            code, _, message = data.partition(' ')
            try:
                code = int(code)
            except ValueError:
                log.error('MI response from OpenSIPS cannot be parsed (neither JSON nor status reply)')
                return
            # we got one of the 'code message' type of replies. This means either parsing error or internal error in OpenSIPS.
            # if we only have one request pending, we can associate the response with it, otherwise is impossible to tell to
            # which request the response corresponds. The failed request will fail with timeout later.
            if len(self.transport.requests) == 1:
                _, request = self.transport.requests.popitem()
                request.deferred.errback(Failure(NegativeReplyError(code, message)))
                log.error('MI request {.method} failed with: {} {}'.format(request, code, message))
            else:
                log.error('Got MI status reply from OpenSIPS that cannot be associated with a request: {!r}'.format(data))
        else:
            try:
                request_id = response['id']
            except KeyError:
                log.error('MI JSON response from OpenSIPS lacks id field')
                return
            if request_id not in self.transport.requests:
                log.error('MI JSON response from OpenSIPS has unknown id: {!r}'.format(request_id))
                return
            request = self.transport.requests.pop(request_id)
            if 'result' in response:
                request.deferred.callback(response['result'])
            elif 'error' in response:
                log.error('MI request {0.method} failed with: {1[error][code]} {1[error][message]}'.format(request, response))
                request.deferred.errback(Failure(NegativeReplyError(response['error']['code'], response['error']['message'])))
            else:
                log.error('Invalid MI JSON response from OpenSIPS')
                request.deferred.errback(Failure(OpenSIPSError('Invalid MI JSON response from OpenSIPS')))


class UNIXSocketConnection(object):
    timeout = 3

    def __init__(self):
        socket_path = process.runtime_file('opensips.sock')
        unlink(socket_path)
        self.path = socket_path
        self.transport = reactor.listenUNIXDatagram(self.path, UNIXSocketProtocol())
        self.transport.requests = {}
        reactor.addSystemEventTrigger('during', 'shutdown', self.close)

    def close(self):
        for request in self.transport.requests.values():
            if not request.deferred.called:
                request.deferred.errback(Error('shutting down'))
        self.transport.requests.clear()
        self.transport.stopListening()
        unlink(self.path)

    def send(self, request):
        try:
            self.transport.write(json.dumps(request.__data__), OpenSIPSConfig.socket_path)
        except socket.error as e:
            log.error("cannot write request to %s: %s" % (OpenSIPSConfig.socket_path, e[1]))
            request.deferred.errback(Failure(Error("Cannot send MI request %s to OpenSIPS" % request.method)))
        else:
            self.transport.requests[request.id] = request
            request.deferred.addBoth(request.process_response)
            reactor.callLater(self.timeout, self._did_timeout, request)
            log.debug('Send MI request: {}'.format(request.__data__))
        return request.deferred

    def _did_timeout(self, request):
        if not request.deferred.called:
            request.deferred.errback(Failure(TimeoutError("OpenSIPS command did timeout")))
            self.transport.requests.pop(request.id)


class ManagementInterface(object):
    __metaclass__ = Singleton
    
    def __init__(self):
        self.connection = UNIXSocketConnection()

    def reload_domains(self):
        return self.connection.send(DomainReload())

    def reload_addresses(self):
        return self.connection.send(AddressReload())

    def end_dialog(self, dialog_id):
        return self.connection.send(EndDialog(dialog_id))

    def get_online_devices(self, account):
        return self.connection.send(GetOnlineDevices(account))

    def refresh_watchers(self, account, refresh_type):
        return self.connection.send(RefreshWatchers(account, refresh_type))

    def update_subscriptions(self, account):
        return self.connection.send(UpdateSubscriptions(account))
