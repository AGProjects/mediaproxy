
import hashlib
import struct
import socket

from application import log
from application.system import host
from base64 import b64encode as base64_encode
from itertools import chain
from collections import deque
from operator import attrgetter
from time import time
from twisted.internet import reactor
from twisted.internet.interfaces import IReadDescriptor
from twisted.internet.protocol import DatagramProtocol
from twisted.internet.error import CannotListenError
from twisted.python.log import Logger
from zope.interface import implementer

from mediaproxy.configuration import RelayConfig
from mediaproxy.interfaces.system import _conntrack
from mediaproxy.iputils import is_routable_ip
from mediaproxy.scheduler import RecurrentCall, KeepRunning

UDP_TIMEOUT_FILE = '/proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream'


rtp_payloads = {
    0: 'G711u', 1: '1016', 2: 'G721', 3: 'GSM', 4: 'G723', 5: 'DVI4', 6: 'DVI4',
    7: 'LPC', 8: 'G711a', 9: 'G722', 10: 'L16', 11: 'L16', 14: 'MPA', 15: 'G728',
    18: 'G729', 25: 'CelB', 26: 'JPEG', 28: 'nv', 31: 'H261', 32: 'MPV', 33: 'MP2T',
    34: 'H263'
}


class RelayPortsExhaustedError(Exception):
    pass


if RelayConfig.relay_ip is None:
    raise RuntimeError('Could not determine default host IP; either add default route or specify relay IP manually')


class SessionLogger(log.ContextualLogger):
    def __init__(self, session):
        super(SessionLogger, self).__init__(logger=log.get_logger())  # use the main logger as backend
        self.session_id = session.call_id

    def apply_context(self, message):
        return '[session {0.session_id}] {1}'.format(self, message) if message != '' else ''


class Address(object):
    """Representation of an endpoint address"""

    def __init__(self, host, port, in_use=True, got_rtp=False):
        self.host = host
        self.port = port
        self.in_use = self.__bool__() and in_use
        self.got_rtp = got_rtp

    def __len__(self):
        return 2

    def __bool__(self):
        return None not in (self.host, self.port)

    def __getitem__(self, index):
        return (self.host, self.port)[index]

    def __contains__(self, item):
        return item in (self.host, self.port)

    def __iter__(self):
        yield self.host
        yield self.port

    def __str__(self):
        return self.__bool__() and ('%s:%d' % (self.host, self.port)) or 'Unknown'

    def __repr__(self):
        return '%s(%r, %r, in_use=%r, got_rtp=%r)' % (self.__class__.__name__, self.host, self.port, self.in_use, self.got_rtp)

    def forget(self):
        self.host, self.port, self.in_use, self.got_rtp = None, None, False, False

    @property
    def unknown(self):
        return None in (self.host, self.port)

    @property
    def obsolete(self):
        return self.__bool__() and not self.in_use


class Counters(dict):
    def __add__(self, other):
        n = Counters(self)
        for k, v in other.items():
            n[k] += v
        return n

    def __iadd__(self, other):
        for k, v in other.items():
            self[k] += v
        return self

    @property
    def caller_bytes(self):
        return self['caller_bytes']

    @property
    def callee_bytes(self):
        return self['callee_bytes']

    @property
    def caller_packets(self):
        return self['caller_packets']

    @property
    def callee_packets(self):
        return self['callee_packets']

    @property
    def relayed_bytes(self):
        return self['caller_bytes'] + self['callee_bytes']

    @property
    def relayed_packets(self):
        return self['caller_packets'] + self['callee_packets']


class StreamListenerProtocol(DatagramProtocol):
    noisy = False

    def __init__(self):
        self.cb_func = None
        self.sdp = None
        self.send_packet_count = 0
        self.stun_queue = []

    def datagramReceived(self, data, addr):
        (host, port) = addr
        if self.cb_func is not None:
            self.cb_func(host, port, data)

    def set_remote_sdp(self, ip, port):
        if is_routable_ip(ip):
            self.sdp = ip, port
        else:
            self.sdp = None

    def send(self, data, is_stun, ip=None, port=None):
        if is_stun:
            self.stun_queue.append(data)

        if ip is None or port is None:
            # this means that we have not received any packets from this host yet,
            # so we have not learnt its address
            if self.sdp is None:
                # we can't do anything if we haven't received the SDP IP yet or
                # it was in a private range
                return
            ip, port = self.sdp

        # we learnt the IP, empty the STUN packets queue
        if self.stun_queue:
            for data in self.stun_queue:
                try:
                    self.transport.write(data, (ip, port))
                except socket.error as e:
                    self.logger.critical('FATAL: cannot write to network socket: %s' % str(e))
            self.stun_queue = []

        if not is_stun:
            if not self.send_packet_count % RelayConfig.userspace_transmit_every:
                try:
                    self.transport.write(data, (ip, port))
                except socket.error as e:
                    self.logger.critical('FATAL: cannot write to network socket: %s' % str(e))

            self.send_packet_count += 1


def _stun_test(data):
    # Check if data is a STUN request and if it's a binding request
    if len(data) < 20:
        return False, False
    msg_type, msg_len, magic = struct.unpack('!HHI', data[:8])
    if msg_type & 0xc == 0 and magic == 0x2112A442:
        if msg_type == 0x0001:
            return True, True
        else:
            return True, False
    else:
        return False, False


class MediaSubParty(object):
    def __init__(self, substream, listener):
        self.substream = substream
        self.logger = substream.logger
        self.listener = listener
        self.listener.protocol.cb_func = self.got_data
        self.remote = Address(None, None)
        host = self.listener.protocol.transport.getHost()
        self.local = Address(host.host, host.port)
        self.timer = None
        self.codec = 'Unknown'
        self.got_stun_probing = False
        self.reset()

    def reset(self):
        if self.timer and self.timer.active():
            self.timer.cancel()
        self.timer = reactor.callLater(RelayConfig.stream_timeout, self.substream.expired, 'no-traffic timeout', RelayConfig.stream_timeout)
        self.remote.in_use = False  # keep remote address around but mark it as obsolete
        self.remote.got_rtp = False
        self.got_stun_probing = False
        self.listener.protocol.send_packet_count = 0

    def before_hold(self):
        if self.timer and self.timer.active():
            self.timer.cancel()
        self.timer = reactor.callLater(RelayConfig.on_hold_timeout, self.substream.expired, 'on hold timeout', RelayConfig.on_hold_timeout)

    def after_hold(self):
        if self.timer and self.timer.active():
            self.timer.cancel()
        if not self.remote.in_use:
            self.timer = reactor.callLater(RelayConfig.stream_timeout, self.substream.expired, 'no-traffic timeout', RelayConfig.stream_timeout)

    def got_data(self, host, port, data):
        if (host, port) == tuple(self.remote):
            if self.remote.obsolete:
                # the received packet matches the previously used IP/port,
                # which has been made obsolete, so ignore it
                return
        else:
            if self.remote.in_use:
                # the received packet is different than the recorded IP/port,
                # so we will discard it
                return
            # we have learnt the remote IP/port
            self.remote.host, self.remote.port = host, port
            self.remote.in_use = True
            self.logger.info('discovered peer: %s' % self.substream.stream)
        is_stun, is_binding_request = _stun_test(data)
        self.substream.send_data(self, data, is_stun)
        if not self.remote.got_rtp and not is_stun:
            # This is the first RTP packet received
            self.remote.got_rtp = True
            if self.timer:
                if self.timer.active():
                    self.timer.cancel()
                self.timer = None
            if self.codec == 'Unknown' and self.substream is self.substream.stream.rtp:
                try:
                    pt = data[1] & 127
                except IndexError:
                    pass
                else:
                    if pt > 95:
                        self.codec = 'Dynamic(%d)' % pt
                    elif pt in rtp_payloads:
                        self.codec = rtp_payloads[pt]
                    else:
                        self.codec = 'Unknown(%d)' % pt
            self.substream.check_create_conntrack()
        if is_binding_request:
            self.got_stun_probing = True

    def cleanup(self):
        if self.timer and self.timer.active():
            self.timer.cancel()
        self.timer = None
        self.listener.protocol.cb_func = None
        self.substream = None


class MediaSubStream(object):
    def __init__(self, stream, listener_caller, listener_callee):
        self.stream = stream
        self.logger = stream.logger
        self.forwarding_rule = None
        self.caller = MediaSubParty(self, listener_caller)
        self.callee = MediaSubParty(self, listener_callee)
        self._counters = Counters(caller_bytes=0, callee_bytes=0, caller_packets=0, callee_packets=0)

    @property
    def counters(self):
        """Accumulated counters from all the forwarding rules the stream had"""
        if self.forwarding_rule is None:
            return self._counters
        else:
            try:
                self.logger.debug(', '.join([f"{key}={self.forwarding_rule.counters[key]}" for key in self.forwarding_rule.counters.keys()]))
                return self._counters + self.forwarding_rule.counters
            except _conntrack.Error:
                return self._counters

    def _stop_relaying(self):
        if self.forwarding_rule is not None:
            try:
                self.logger.info(', '.join([f"{key}={self.forwarding_rule.counters[key]}" for key in self.forwarding_rule.counters.keys()]))
                self._counters += self.forwarding_rule.counters
            except _conntrack.Error:
                pass
            self.forwarding_rule = None

    def reset(self, party):
        if party == 'caller':
            self.caller.reset()
        else:
            self.callee.reset()
        self._stop_relaying()

    def check_create_conntrack(self):
        if self.stream.first_media_time is None:
            self.stream.first_media_time = time()
        if self.caller.remote.in_use and self.caller.remote.got_rtp and self.callee.remote.in_use and self.callee.remote.got_rtp:
            self.forwarding_rule = _conntrack.ForwardingRule(self.caller.remote, self.caller.local, self.callee.remote, self.callee.local, self.stream.session.mark)
            self.forwarding_rule.expired_func = self.conntrack_expired

    def send_data(self, source, data, is_stun):
        if source is self.caller:
            dest = self.callee
        else:
            dest = self.caller
        if dest.remote:
            # if we have already learnt the remote address of the destination, use that
            ip, port = dest.remote.host, dest.remote.port
            dest.listener.protocol.send(data, is_stun, ip, port)
        else:
            # otherwise use the IP/port specified in the SDP, if public
            dest.listener.protocol.send(data, is_stun)

    def conntrack_expired(self):
        try:
            timeout_wait = int(open(UDP_TIMEOUT_FILE).read())
        except:
            timeout_wait = 0
        self.expired('conntrack timeout', timeout_wait)

    def expired(self, reason, timeout_wait):
        self._stop_relaying()
        self.stream.substream_expired(self, reason, timeout_wait)

    def cleanup(self):
        self.caller.cleanup()
        self.callee.cleanup()
        self._stop_relaying()
        self.stream = None


class MediaParty(object):
    def __init__(self, stream, party):
        self.manager = stream.session.manager
        self.logger = stream.logger
        self._remote_sdp = None
        self.is_on_hold = False
        self.uses_ice = False
        while True:
            self.listener_rtp = None
            self.ports = port_rtp, port_rtcp = self.manager.get_ports()
            listen_ip = None
            if RelayConfig.auto_detect_interfaces and not RelayConfig.advertised_ip:
                if party == 'callee' and stream.session.destination_ip:
                    listen_ip = host.outgoing_ip_for(stream.session.destination_ip)
                else:
                    listen_ip = host.outgoing_ip_for(stream.session.caller_ip)

            try:
                self.listener_rtp = reactor.listenUDP(port_rtp, StreamListenerProtocol(), interface=listen_ip or RelayConfig.relay_ip)
                self.listener_rtcp = reactor.listenUDP(port_rtcp, StreamListenerProtocol(), interface=listen_ip or RelayConfig.relay_ip)
            except CannotListenError:
                if self.listener_rtp is not None:
                    self.listener_rtp.stopListening()
                self.manager.set_bad_ports(self.ports)
                self.logger.warning('Cannot use port pair %d/%d' % self.ports)
            else:
                break

    def _get_remote_sdp(self):
        return self._remote_sdp

    def _set_remote_sdp(self, addr):
        (ip, port) = addr
        self._remote_sdp = ip, port
        self.listener_rtp.protocol.set_remote_sdp(ip, port)

    remote_sdp = property(_get_remote_sdp, _set_remote_sdp)

    def cleanup(self):
        self.listener_rtp.stopListening()
        self.listener_rtcp.stopListening()
        self.manager.free_ports(self.ports)
        self.manager = None


class MediaStream(object):
    def __init__(self, session, media_type, media_ip, media_port, direction, media_parameters, initiating_party):
        self.is_alive = True
        self.session = session  # type: Session
        self.logger = session.logger
        self.media_type = media_type
        self.caller = MediaParty(self, 'caller')
        self.callee = MediaParty(self, 'callee')
        self.rtp = MediaSubStream(self, self.caller.listener_rtp, self.callee.listener_rtp)
        self.rtcp = MediaSubStream(self, self.caller.listener_rtcp, self.callee.listener_rtcp)
        getattr(self, initiating_party).remote_sdp = (media_ip, media_port)
        getattr(self, initiating_party).uses_ice = (media_parameters.get('ice', 'no') == 'yes')
        self.check_hold(initiating_party, direction, media_ip)
        self.create_time = time()
        self.first_media_time = None
        self.start_time = None
        self.end_time = None
        self.status = 'active'
        self.timeout_wait = 0

    def __str__(self):
        if self.caller.remote_sdp is None:
            src = 'Unknown'
        else:
            src = '%s:%d' % self.caller.remote_sdp
        if self.caller.is_on_hold:
            src += ' ON HOLD'
        if self.caller.uses_ice:
            src += ' (ICE)'
        if self.callee.remote_sdp is None:
            dst = 'Unknown'
        else:
            dst = '%s:%d' % self.callee.remote_sdp
        if self.callee.is_on_hold:
            dst += ' ON HOLD'
        if self.callee.uses_ice:
            dst += ' (ICE)'
        rtp = self.rtp
        rtcp = self.rtcp
        return '(%s) %s (RTP: %s, RTCP: %s) <-> %s <-> %s <-> %s (RTP: %s, RTCP: %s)' % (
            self.media_type, src, rtp.caller.remote, rtcp.caller.remote, rtp.caller.local, rtp.callee.local, dst, rtp.callee.remote, rtcp.callee.remote)

    @property
    def counters(self):
        return self.rtp.counters + self.rtcp.counters

    @property
    def uses_ice(self):
        return self.caller.uses_ice and self.callee.uses_ice

    @property
    def is_on_hold(self):
        return self.caller.is_on_hold or self.callee.is_on_hold

    def check_hold(self, party, direction, ip):
        previous_hold = self.is_on_hold
        party = getattr(self, party)
        if direction == 'sendonly' or direction == 'inactive':
            party.is_on_hold = True
        elif ip == '0.0.0.0':
            party.is_on_hold = True
        else:
            party.is_on_hold = False
        if previous_hold and not self.is_on_hold:
            for substream in [self.rtp, self.rtcp]:
                for subparty in [substream.caller, substream.callee]:
                    self.status = 'active'
                    subparty.after_hold()
        if not previous_hold and self.is_on_hold:
            for substream in [self.rtp, self.rtcp]:
                for subparty in [substream.caller, substream.callee]:
                    self.status = 'on hold'
                    subparty.before_hold()

    def reset(self, party, media_ip, media_port):
        self.rtp.reset(party)
        self.rtcp.reset(party)
        getattr(self, party).remote_sdp = (media_ip, media_port)

    def substream_expired(self, substream, reason, timeout_wait):
        if substream is self.rtp and self.caller.uses_ice and self.callee.uses_ice:
            reason = 'unselected ICE candidate'
            self.logger.info('RTP stream expired: {}'.format(reason))
            if not substream.caller.got_stun_probing and not substream.callee.got_stun_probing:
                self.logger.info('unselected ICE candidate, but no STUN was received')

        if substream is self.rtcp:
            # Forget about the remote addresses, this will cause any
            # re-occurrence of the same traffic to be forwarded again
            substream.caller.remote.forget()
            substream.caller.listener.protocol.send_packet_count = 0
            substream.callee.remote.forget()
            substream.callee.listener.protocol.send_packet_count = 0
        else:
            session = self.session
            self.cleanup(reason)
            self.timeout_wait = timeout_wait
            session.stream_expired(self)

    def cleanup(self, status='closed'):
        if self.is_alive:
            self.is_alive = False
            self.status = status
            self.caller.cleanup()
            self.callee.cleanup()
            self.rtp.cleanup()
            self.rtcp.cleanup()
            self.session = None
            self.end_time = time()


class Session(object):
    def __init__(self, manager, dispatcher, call_id, from_tag, from_uri, to_tag, to_uri, cseq, user_agent, media_list, is_downstream, is_caller_cseq, mark=0, caller_ip=None, destination_ip=None):
        self.manager = manager
        self.dispatcher = dispatcher
        self.session_id = base64_encode(hashlib.md5(call_id.encode()).digest()).rstrip(b'=')
        self.call_id = call_id
        self.caller_ip = caller_ip
        self.destination_ip = destination_ip
        self.from_tag = from_tag
        self.to_tag = None
        self.mark = mark
        self.from_uri = from_uri
        self.to_uri = to_uri
        self.caller_ua = None
        self.callee_ua = None
        self.cseq = None
        self.previous_cseq = None
        self.streams = {}
        self.start_time = None
        self.end_time = None
        self.logger = SessionLogger(self)
        self.logger.info('created: from-tag {0.from_tag})'.format(self))
        self.update_media(cseq, to_tag, user_agent, media_list, is_downstream, is_caller_cseq)

    def update_media(self, cseq, to_tag, user_agent, media_list, is_downstream, is_caller_cseq):
        if self.cseq is None:
            old_cseq = (0, 0)
        else:
            old_cseq = self.cseq
        if is_caller_cseq:
            cseq = (cseq, old_cseq[1])
            if self.to_tag is None and to_tag is not None:
                self.to_tag = to_tag
        else:
            cseq = (old_cseq[0], cseq)
        if is_downstream:
            party = 'caller'
            if self.caller_ua is None:
                self.caller_ua = user_agent
        else:
            party = 'callee'
            if self.callee_ua is None:
                self.callee_ua = user_agent
        if self.cseq is None or cseq > self.cseq:
            if not media_list:
                return
            self.logger.info('got SDP offer')
            self.streams[cseq] = new_streams = []
            if self.cseq is None:
                old_streams = []
            else:
                old_streams = self.streams[self.cseq]
            for media_type, media_ip, media_port, media_direction, media_parameters in media_list:
                for old_stream in old_streams:
                    old_remote = getattr(old_stream, party).remote_sdp
                    if old_remote is not None:
                        old_ip, old_port = old_remote
                    else:
                        old_ip, old_port = None, None
                    if old_stream.is_alive and old_stream.media_type == media_type and ((media_ip, media_port) in ((old_ip, old_port), ('0.0.0.0', old_port), (old_ip, 0))):
                        stream = old_stream
                        stream.check_hold(party, media_direction, media_ip)
                        if media_port == 0:
                            self.logger.info('disabled stream: %s', stream)
                        else:
                            self.logger.info('retained stream: %s', stream)
                        break
                else:
                    stream = MediaStream(self, media_type, media_ip, media_port, media_direction, media_parameters, party)
                    self.logger.info('proposed stream: %s' % stream)
                if media_port == 0:
                    stream.cleanup()
                new_streams.append(stream)
            if self.previous_cseq is not None:
                for stream in self.streams[self.previous_cseq]:
                    if stream not in self.streams[self.cseq] + new_streams:
                        stream.cleanup()
            self.previous_cseq = self.cseq
            self.cseq = cseq
        elif self.cseq == cseq:
            self.logger.info('got SDP answer')
            now = time()
            if self.start_time is None:
                self.start_time = now
            current_streams = self.streams[cseq]
            for stream in current_streams:
                if stream.start_time is None:
                    stream.start_time = now
            if to_tag is not None and not media_list:
                return
            if len(media_list) < len(current_streams):
                for stream in current_streams[len(media_list):]:
                    self.logger.info('removed! stream: %s' % stream)
                    stream.cleanup('rejected')
            for stream, (media_type, media_ip, media_port, media_direction, media_parameters) in zip(current_streams, media_list):
                if stream.media_type != media_type:
                    raise ValueError('Media types do not match: %r and %r' % (stream.media_type, media_type))
                if media_port == 0:
                    if stream.is_alive:
                        self.logger.info('rejected stream: %s' % stream)
                    else:
                        self.logger.info('disabled stream: %s' % stream)
                    stream.cleanup('rejected')
                    continue
                stream.check_hold(party, media_direction, media_ip)
                party_info = getattr(stream, party)
                party_info.uses_ice = (media_parameters.get('ice', 'no') == 'yes')
                if party_info.remote_sdp is None or party_info.remote_sdp[0] == '0.0.0.0':
                    party_info.remote_sdp = (media_ip, media_port)
                    self.logger.info('accepted stream: %s' % stream)
                else:
                    if party_info.remote_sdp[1] != media_port or (party_info.remote_sdp[0] != media_ip != '0.0.0.0'):
                        stream.reset(party, media_ip, media_port)
                        self.logger.info('updating stream: %s' % stream)
                    else:
                        self.logger.info('retained stream: %s' % stream)
            if self.previous_cseq is not None:
                for stream in [stream for stream in self.streams[self.previous_cseq] if stream not in current_streams]:
                    self.logger.info('removing stream: %s' % stream)
                    stream.cleanup()
        else:
            self.logger.info('got old CSeq %d:%d, ignoring' % cseq)

    def get_local_media(self, is_downstream, cseq, is_caller_cseq):
        if is_caller_cseq:
            pos = 0
        else:
            pos = 1
        try:
            cseq = max(key for key in list(self.streams.keys()) if key[pos] == cseq)
        except ValueError:
            return None
        if is_downstream:
            retval = [(stream.status in ['active', 'on hold']) and tuple(stream.rtp.callee.local) or (stream.rtp.callee.local.host, 0) for stream in self.streams[cseq]]
        else:
            retval = [(stream.status in ['active', 'on hold']) and tuple(stream.rtp.caller.local) or (stream.rtp.caller.local.host, 0) for stream in self.streams[cseq]]
        self.logger.info('SDP media ip for %s set to %s:%d' % ("callee" if is_downstream else "caller", retval[0][0], retval[0][1]))
        return retval

    def cleanup(self):
        self.end_time = time()
        for cseq in [self.previous_cseq, self.cseq]:
            if cseq is not None:
                for stream in self.streams[cseq]:
                    stream.cleanup()

    def stream_expired(self, stream):
        active_streams = set()
        for cseq in [self.previous_cseq, self.cseq]:
            if cseq is not None:
                active_streams.update({stream for stream in self.streams[cseq] if stream.is_alive})
        if len(active_streams) == 0:
            self.manager.session_expired(self.call_id, self.from_tag)

    @property
    def duration(self):
        if self.start_time is not None:
            if self.end_time is not None:
                return int(self.end_time - self.start_time)
            else:
                return int(time() - self.start_time)
        else:
            return 0

    @property
    def broken(self):
        uses_ice = False
        for s in self.streams.values():
            for m in s:
                if m.uses_ice:
                    uses_ice = True
                    break
        #uses_ice = any(s for s in self.streams.values() if s.uses_ice)
        return self.duration > 90 and not self.relayed_bytes and not uses_ice

    @property
    def relayed_bytes(self):
        return sum(stream.counters.relayed_bytes for stream in set(chain(*iter(self.streams.values()))))

    @property
    def statistics(self):
        all_streams = set(chain(*iter(self.streams.values())))
        attributes = ('call_id', 'from_tag', 'from_uri', 'to_tag', 'to_uri', 'start_time', 'duration')
        stats = dict((name, getattr(self, name)) for name in attributes)
        stats['caller_ua'] = self.caller_ua or 'Unknown'
        stats['callee_ua'] = self.callee_ua or 'Unknown'
        stats['streams'] = streams = []
        stream_attributes = ('media_type', 'status', 'timeout_wait')
        streams_to_sort = []
        for stream in all_streams:
            try:
                if stream and stream.start_time:
                    streams_to_sort.append(stream)
            except AttributeError:
                pass
        for stream in sorted(streams_to_sort, key=attrgetter('start_time')):  # type: MediaStream
            info = dict((name, getattr(stream, name)) for name in stream_attributes)
            info['caller_codec'] = stream.rtp.caller.codec
            info['callee_codec'] = stream.rtp.callee.codec
            if stream.start_time is None:
                info['start_time'] = info['end_time'] = None
            elif self.start_time is None:
                info['start_time'] = info['end_time'] = 0
            else:
                info['start_time'] = max(int(stream.start_time - self.start_time), 0)
                if stream.status == 'rejected':
                    info['end_time'] = info['start_time']
                else:
                    if stream.end_time is None:
                        info['end_time'] = stats['duration']
                    else:
                        info['end_time'] = min(int(stream.end_time - self.start_time), self.duration)
            if stream.first_media_time is None:
                info['post_dial_delay'] = None
            else:
                info['post_dial_delay'] = stream.first_media_time - stream.create_time
            caller = stream.rtp.caller
            callee = stream.rtp.callee
            info.update(stream.counters)
            info['caller_local'] = str(caller.local)
            info['callee_local'] = str(callee.local)
            info['caller_remote'] = str(caller.remote)
            info['callee_remote'] = str(callee.remote)
            streams.append(info)
        return stats


class SessionManager(Logger):
    @implementer(IReadDescriptor)

    def __init__(self, relay, start_port, end_port):
        self.relay = relay
        self.ports = deque((i, i + 1) for i in range(start_port, end_port, 2))
        self.bad_ports = deque()
        self.sessions = {}
        self.watcher = _conntrack.ExpireWatcher()
        self.active_byte_counter = 0  # relayed byte counter for sessions active during last speed measurement
        self.closed_byte_counter = 0  # relayed byte counter for sessions closed after last speed measurement
        self.bps_relayed = 0
        if RelayConfig.traffic_sampling_period > 0:
            self.speed_calculator = RecurrentCall(RelayConfig.traffic_sampling_period, self._measure_speed)
        else:
            self.speed_calculator = None
        reactor.addReader(self)

    def _measure_speed(self):
        start_time = time()
        current_byte_counter = sum(session.relayed_bytes for session in self.sessions.values())
        self.bps_relayed = 8 * (current_byte_counter + self.closed_byte_counter - self.active_byte_counter) / RelayConfig.traffic_sampling_period
        self.active_byte_counter = current_byte_counter
        self.closed_byte_counter = 0
        us_taken = int((time() - start_time) * 1000000)
        if us_taken > 10000:
            log.warning('Aggregate speed calculation time exceeded 10ms: %d us for %d sessions' % (us_taken, len(self.sessions)))
        return KeepRunning

    # implemented for IReadDescriptor
    def fileno(self):
        return self.watcher.fd

    def doRead(self):
        stream = self.watcher.read()
        if stream:
            stream.expired_func()

    def connectionLost(self, reason):
        reactor.removeReader(self)

    @property
    def broken_sessions(self):
        return set(session.call_id for session in self.sessions.values() if session.broken)

    # port management
    def get_ports(self):
        if len(self.bad_ports) > len(self.ports):
            log.debug('Excessive amount of bad ports, doing cleanup')
            self.ports.extend(self.bad_ports)
            self.bad_ports = deque()
        try:
            return self.ports.popleft()
        except IndexError:
            raise RelayPortsExhaustedError()

    def set_bad_ports(self, ports):
        self.bad_ports.append(ports)

    def free_ports(self, ports):
        self.ports.append(ports)

    # called by higher level
    def _find_session_key(self, call_id, from_tag, to_tag):
        key_from = (call_id, from_tag)
        if key_from in self.sessions:
            return key_from
        if to_tag:
            key_to = (call_id, to_tag)
            if key_to in self.sessions:
                return key_to
        return None

    def has_session(self, call_id, from_tag, to_tag=None, **kw):
        return any((call_id, tag) in self.sessions for tag in (from_tag, to_tag) if tag is not None)

    def update_session(self, dispatcher, call_id, from_tag, from_uri, to_uri, cseq, user_agent, type, media=[], to_tag=None, **kw):
        key = self._find_session_key(call_id, from_tag, to_tag)
        try:
            (signaling_ip, destination_ip) = kw['signaling_ip'].split("_")
        except ValueError:
            signaling_ip = kw['signaling_ip']
            destination_ip = None

        if key:
            session = self.sessions[key]
            is_downstream = (session.from_tag != from_tag) ^ (type == 'request')
            is_caller_cseq = (session.from_tag == from_tag)
            session.update_media(cseq, to_tag, user_agent, media, is_downstream, is_caller_cseq)
        elif type == 'reply' and not media:
            return None
        else:
            is_downstream = type == 'request'
            is_caller_cseq = True
            session = Session(self, dispatcher, call_id, from_tag, from_uri, to_tag, to_uri, cseq, user_agent, media, is_downstream, is_caller_cseq, caller_ip=signaling_ip, destination_ip=destination_ip)
            self.sessions[(call_id, from_tag)] = session
            self.relay.add_session(dispatcher)
        return session.get_local_media(is_downstream, cseq, is_caller_cseq)

    def remove_session(self, call_id, from_tag, to_tag=None, **kw):
        key = self._find_session_key(call_id, from_tag, to_tag)
        try:
            session = self.sessions[key]
        except KeyError:
            log.warning('The dispatcher tried to remove a session which is no longer present on the relay')
            return None
        session.logger.info('removed')
        session.cleanup()
        self.closed_byte_counter += session.relayed_bytes
        del self.sessions[key]
        reactor.callLater(0, self.relay.remove_session, session.dispatcher)
        return session

    def session_expired(self, call_id, from_tag):
        key = (call_id, from_tag)
        try:
            session = self.sessions[key]
        except KeyError:
            log.warning('A session expired but is no longer present on the relay')
            return
        session.logger.info('expired')
        session.cleanup()
        self.closed_byte_counter += session.relayed_bytes
        del self.sessions[key]
        self.relay.session_expired(session)
        self.relay.remove_session(session.dispatcher)

    def cleanup(self):
        if self.speed_calculator is not None:
            self.speed_calculator.cancel()
        for key in list(self.sessions.keys()):
            self.session_expired(*key)

    @property
    def statistics(self):
        return [session.statistics for session in self.sessions.values()]

    @property
    def stream_count(self):
        stream_count = {}
        for session in self.sessions.values():
            for stream in set(chain(*iter(session.streams.values()))):
                if stream.is_alive:
                    stream_count[stream.media_type] = stream_count.get(stream.media_type, 0) + 1
        return stream_count
