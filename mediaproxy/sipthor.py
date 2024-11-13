
"""SIP Thor backend"""

from application import log
from application.python.queue import EventQueue
from gnutls.interfaces.twisted import TLSContext
from thor.entities import ThorEntities, GenericThorEntity
from thor.eventservice import EventServiceClient, ThorEvent
from thor.scheduler import RecurrentCall, KeepRunning
from thor.tls import X509Credentials

from mediaproxy import __version__
from mediaproxy.configuration import ThorNetworkConfig
from mediaproxy.configuration.datatypes import DispatcherIPAddress
from mediaproxy.relay import SRVMediaRelayBase


if ThorNetworkConfig.domain is None:
    # SIP Thor is installed but disabled. Fake an ImportError to start in standalone media relay mode.
    log.warning('SIP Thor is installed but disabled from the configuration')
    raise ImportError('SIP Thor is disabled')


# Tasks
#
class Task(object):
    def __init__(self, action, data=None, **kwargs):
        self.action = action
        self.data = data
        for name in kwargs:
            setattr(self, name, kwargs[name])

    def __str__(self):
        return "%s %s" % (self.action, self.data)

# noinspection PyAbstractClass
class SIPThorMediaRelayBase(SRVMediaRelayBase, EventServiceClient):
    topics = ['Thor.Members']

    def __init__(self):
        self.node = GenericThorEntity(ThorNetworkConfig.node_ip, ['media_relay'], version=__version__)
        self.presence_message = ThorEvent('Thor.Presence', self.node.id)
        self.shutdown_message = ThorEvent('Thor.Leave', self.node.id)
        self.sipthor_dispatchers = []
        self.additional_dispatchers = []
        credentials = X509Credentials(cert_name='relay')
        tls_context = TLSContext(credentials)
        EventServiceClient.__init__(self, ThorNetworkConfig.domain, tls_context)
        SRVMediaRelayBase.__init__(self)

        self.statistics_task = RecurrentCall(30, self._notify_statistics)
        self.statistics = {}
        self.task_queue = EventQueue(handler=self.handle_tasks, name='TaskHandler')
        self.task_queue.start()

    def handle_tasks(self, task):
        """Handle the Thor network events (node join, node leave, expirations and notifications)"""
        if not isinstance(task, Task):
            # This shouldn't happen as they are internal tasks, but log the error to catch programming mistakes.
            log.error("handle_task received a non-Task entity of type '%s' (ignored)" % str(type(task)))
            return
        try:
            handler = getattr(self, '_TH_%s' % task.action)
        except AttributeError:
            log.error("no handler for task '%s'" % task.action)
            return
        try:
            handler(task)
        except Exception:
            log.exception("captured unhandled exception while processing task: %s" % task)

    def _notify_statistics(self):
        """Periodic usage publication"""
        if self.disconnecting:
            return
        self.task_queue.put(Task('publish_statistics'))
        return KeepRunning

    def _TH_publish_statistics(self, task):
        pass
            
    def handle_event(self, event):
        if not self.shutting_down:
            sip_proxy_ips = [node.ip for node in ThorEntities(event.message, role='sip_proxy')]
            self.sipthor_dispatchers = [(ip, DispatcherIPAddress.default_port) for ip in sip_proxy_ips]
            self.update_dispatchers(self.sipthor_dispatchers + self.additional_dispatchers)

    def _cb_got_all(self, results):
        if not self.shutting_down:
            self.additional_dispatchers = [result[1] for result in results if result[0] and result[1] is not None]
            self.update_dispatchers(self.sipthor_dispatchers + self.additional_dispatchers)

    def _shutdown_done(self):
        EventServiceClient._shutdown(self)
