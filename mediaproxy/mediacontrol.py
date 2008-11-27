# Copyright (C) 2008 AG Projects
# Author: Ruud Klaver <ruud@ag-projects.com>
#

from time import time
from collections import deque
from operator import attrgetter
from itertools import chain

from zope.interface import implements
from twisted.internet import reactor
from twisted.internet.interfaces import IReadDescriptor
from twisted.internet.protocol import DatagramProtocol
from twisted.internet.error import CannotListenError
from twisted.python.log import Logger

from application import log
from application.system import default_host_ip
from application.configuration import *

from mediaproxy.interfaces.system import _conntrack
from mediaproxy import configuration_filename
from mediaproxy.iputils import is_routable_ip

UDP_TIMEOUT_FILE = "/proc/sys/net/ipv4/netfilter/ip_conntrack_udp_timeout_stream"

rtp_payloads = {
     0: "G711u", 1: "1016",  2: "G721",  3: "GSM",  4: "G723",  5: "DVI4", 6: "DVI4",
     7: "LPC",   8: "G711a", 9: "G722", 10: "L16", 11: "L16",  14: "MPA", 15: "G728",
    18: "G729", 25: "CelB", 26: "JPEG", 28: "nv",  31: "H261", 32: "MPV", 33: "MP2T",
    34: "H263"
}

class Config(ConfigSection):
    _datatypes = {"relay_ip": datatypes.IPAddress}
    relay_ip = default_host_ip
    stream_timeout = 90
    on_hold_timeout = 7200
    traffic_sampling_period = 15
    userspace_transmit_every = 1

configuration = ConfigFile(configuration_filename)
configuration.read_settings("Relay", Config)

if Config.relay_ip is None:
    raise RuntimeError("Could not determine default host IP; either add default route or specify relay IP manually")

class StreamListenerProtocol(DatagramProtocol):
    noisy = False

    def __init__(self):
        self.cb_func = None
        self.sdp = None

    def datagramReceived(self, data, (host, port)):
        if self.cb_func is not None:
            self.cb_func(host, port, data)

    def set_remote_sdp(self, ip, port):
        if is_routable_ip(ip):
            self.send_packet_count = 0
            self.sdp = ip, port
        else:
            self.sdp = None

    def send(self, data):
        host = self.transport.getHost()
        if self.sdp is not None:
            ip, port = self.sdp
            if not self.send_packet_count % Config.userspace_transmit_every:
                self.transport.write(data, (ip, port))
            self.send_packet_count +=1


class MediaSubParty(object):

    def __init__(self, substream, listener):
        self.substream = substream
        self.listener = listener
        self.listener.protocol.cb_func = self.got_data
        self.remote = None
        host = self.listener.protocol.transport.getHost()
        self.local = (host.host, host.port)
        self.bytes = 0
        self.packets = 0
        self.timer = None
        self.codec = "Unknown"
        self.reset(True)

    def reset(self, expire):
        self.got_remote = False
        if self.timer and self.timer.active():
            self.timer.cancel()
        if expire:
            self.timer = reactor.callLater(Config.stream_timeout, self.substream.expired, "no traffic timeout", Config.stream_timeout)
        else:
            self.timer = None
            self.remote = None

    def before_hold(self):
        if self.timer and self.timer.active():
            self.timer.cancel()
        self.timer = reactor.callLater(Config.on_hold_timeout, self.substream.expired, "on hold timeout", Config.on_hold_timeout)

    def after_hold(self):
        if self.timer and self.timer.active():
            self.timer.cancel()
        if not self.got_remote:
            self.timer = reactor.callLater(Config.stream_timeout, self.substream.expired, "no traffic timeout", Config.stream_timeout)

    def got_data(self, host, port, data):
        if not self.got_remote:
            if (host, port) == self.remote:
                return
            self.substream.send_data(self, data)
            if self.timer:
                self.timer.cancel()
                self.timer = None
            if self.codec == "Unknown" and self.substream is self.substream.stream.rtp:
                try:
                    pt = ord(data[1]) & 127
                except IndexError:
                    pass
                else:
                    if pt > 95:
                        self.codec = "Dynamic(%d)" % pt
                    elif pt in rtp_payloads:
                        self.codec = rtp_payloads[pt]
                    else:
                        self.codec = "Unknown(%d)" % pt
            self.got_remote = True
            self.remote = (host, port)
            self.substream.check_create_conntrack()
        else:
            if (host, port) == self.remote:
                self.substream.send_data(self, data)

    def cleanup(self):
        if self.timer and self.timer.active():
            self.timer.cancel()
        self.timer = None
        self.listener.protocol.cb_func = None
        self.substream = None


class MediaSubStream(object):

    def __init__(self, stream, listener_caller, listener_callee):
        self.stream = stream
        self.forwarding_rule = None
        self.caller = MediaSubParty(self, listener_caller)
        self.callee = MediaSubParty(self, listener_callee)

    @property
    def caller_bytes(self):
        if self.forwarding_rule is None:
            return self.caller.bytes
        else:
            return self.caller.bytes + self.forwarding_rule.caller_bytes

    @property
    def caller_packets(self):
        if self.forwarding_rule is None:
            return self.caller.packets
        else:
            return self.caller.packets + self.forwarding_rule.caller_packets

    @property
    def callee_bytes(self):
        if self.forwarding_rule is None:
            return self.callee.bytes
        else:
            return self.callee.bytes + self.forwarding_rule.callee_bytes

    @property
    def callee_packets(self):
        if self.forwarding_rule is None:
            return self.callee.packets
        else:
            return self.callee.packets + self.forwarding_rule.callee_packets

    def _update_counters(self):
        self.caller.bytes += self.forwarding_rule.caller_bytes
        self.caller.packets += self.forwarding_rule.caller_packets
        self.callee.bytes += self.forwarding_rule.callee_bytes
        self.callee.packets += self.forwarding_rule.callee_packets

    def _stop_relaying(self):
        if self.forwarding_rule is not None:
            self._update_counters()
            self.forwarding_rule = None

    def reset(self, party):
        if party == "caller":
            self.caller.reset(True)
        else:
            self.callee.reset(True)
        self._stop_relaying()

    def check_create_conntrack(self):
        log.debug("Got traffic information for stream: %s" % self.stream)
        if self.stream.first_media_time is None:
            self.stream.first_media_time = time()
        if self.caller.got_remote and self.callee.got_remote:
            self.forwarding_rule = _conntrack.ForwardingRule(self.caller.remote, self.caller.local, self.callee.remote, self.callee.local, self.stream.session.mark)
            self.forwarding_rule.expired_func = self.conntrack_expired

    def send_data(self, source, data):
        if source is self.caller:
            dest = self.callee
        else:
            dest = self.caller
        dest.listener.protocol.send(data)

    def conntrack_expired(self):
        try:
            timeout_wait = int(open(UDP_TIMEOUT_FILE).read())
        except:
            timeout_wait = 0
        self.expired("conntrack timeout", timeout_wait)

    def expired(self, reason, timeout_wait):
        self._stop_relaying()
        self.stream.substream_expired(self, reason, timeout_wait)

    def cleanup(self):
        self.caller.cleanup()
        self.callee.cleanup()
        self._stop_relaying()
        self.stream = None


class MediaParty(object):

    def __init__(self, stream):
        self.manager = stream.session.manager
        self._remote_sdp = None
        self.is_on_hold = False
        while True:
            self.listener_rtp = None
            self.ports = port_rtp, port_rtcp = self.manager.get_ports()
            try:
                self.listener_rtp = reactor.listenUDP(port_rtp, StreamListenerProtocol(), interface=Config.relay_ip)
                self.listener_rtcp = reactor.listenUDP(port_rtcp, StreamListenerProtocol(), interface=Config.relay_ip)
            except CannotListenError:
                if self.listener_rtp is not None:
                    self.listener_rtp.stopListening()
                self.manager.set_bad_ports(self.ports)
                log.warn("Cannot use port pair %d/%d" % self.ports)
            else:
                break

    def _get_remote_sdp(self):
        return self._remote_sdp

    def _set_remote_sdp(self, (ip, port)):
        self._remote_sdp = ip, port
        self.listener_rtp.protocol.set_remote_sdp(ip, port)
    remote_sdp = property(_get_remote_sdp, _set_remote_sdp)

    def cleanup(self):
        self.listener_rtp.stopListening()
        self.listener_rtcp.stopListening()
        self.manager.free_ports(self.ports)
        self.manager = None

class MediaStream(object):

    def __init__(self, session, media_type, media_ip, media_port, initiating_party, direction = None):
        self.is_alive = True
        self.session = session
        self.media_type = media_type
        self.caller = MediaParty(self)
        self.callee = MediaParty(self)
        self.rtp = MediaSubStream(self, self.caller.listener_rtp, self.callee.listener_rtp)
        self.rtcp = MediaSubStream(self, self.caller.listener_rtcp, self.callee.listener_rtcp)
        getattr(self, initiating_party).remote_sdp = (media_ip, media_port)
        self.check_hold(initiating_party, direction, media_ip)
        self.create_time = time()
        self.first_media_time = None
        self.start_time = None
        self.end_time = None
        self.status = "active"
        self.timeout_wait = 0

    def __str__(self):
        if self.caller.remote_sdp is None:
            src = "Unknown"
        else:
            src = "%s:%d" % self.caller.remote_sdp
        if self.caller.is_on_hold:
            src += " ON HOLD"
        if self.callee.remote_sdp is None:
            dst = "Unknown"
        else:
            dst = "%s:%d" % self.callee.remote_sdp
        if self.callee.is_on_hold:
            dst += " ON HOLD"
        for val, sub_party in zip(["src_rtp", "src_rtcp", "dst_rtp", "dst_rtcp"], [self.rtp.caller, self.rtcp.caller, self.rtp.callee, self.rtcp.callee]):
            if sub_party.got_remote:
                exec("%s = '%s:%d'" % ((val,) + sub_party.remote))
            else:
                exec("%s = 'Unknown'" % val)
        src_local = "%s:%d" % self.rtp.caller.local
        dst_local = "%s:%d" % self.rtp.callee.local
        return "(%s) %s (RTP: %s, RTCP: %s) <-> %s <-> %s <-> %s (RTP: %s, RTCP: %s)" % (self.media_type, src, src_rtp, src_rtcp, src_local, dst_local, dst, dst_rtp, dst_rtcp)

    @property
    def is_on_hold(self):
        return self.caller.is_on_hold or self.callee.is_on_hold

    def check_hold(self, party, direction, ip):
        previous_hold = self.is_on_hold
        party = getattr(self, party)
        if direction == "sendonly" or direction == "inactive":
            party.is_on_hold = True
        elif ip == "0.0.0.0":
            party.is_on_hold = True
        else:
            party.is_on_hold = False
        if previous_hold and not self.is_on_hold:
            for substream in [self.rtp, self.rtcp]:
                for subparty in [substream.caller, substream.callee]:
                    self.status = "active"
                    subparty.after_hold()
        if not previous_hold and self.is_on_hold:
            for substream in [self.rtp, self.rtcp]:
                for subparty in [substream.caller, substream.callee]:
                    self.status = "on hold"
                    subparty.before_hold()

    def reset(self, party, media_ip, media_port):
        self.rtp.reset(party)
        self.rtcp.reset(party)
        getattr(self, party).remote_sdp = (media_ip, media_port)

    def substream_expired(self, substream, reason, timeout_wait):
        # This will cause any re-occuronce of the same traffic to be forwarded again
        if substream is self.rtcp:
            substream.caller.reset(False)
            substream.callee.reset(False)
        else:
            session = self.session
            self.cleanup(reason)
            self.timeout_wait = timeout_wait
            session.stream_expired(self)

    def cleanup(self, status="closed"):
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

    def __init__(self, manager, dispatcher, call_id, from_tag, from_uri, to_tag, to_uri, cseq, user_agent, media_list, is_downstream, is_caller_cseq, mark = 0):
        self.manager = manager
        self.dispatcher = dispatcher
        self.call_id = call_id
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
        self.update_media(cseq, to_tag, user_agent, media_list, is_downstream, is_caller_cseq)

    def __str__(self):
        return "%s: %s (%s) --> %s" % (self.call_id, self.from_uri, self.from_tag, self.to_uri)

    def update_media(self, cseq, to_tag, user_agent, media_list, is_downstream, is_caller_cseq):
        if self.cseq is None:
            old_cseq = (0,0)
        else:
            old_cseq = self.cseq
        if is_caller_cseq:
            cseq = (cseq, old_cseq[1])
            if self.to_tag is None and to_tag is not None:
                self.to_tag = to_tag
        else:
            cseq = (old_cseq[0], cseq)
        if is_downstream:
            party = "caller"
            if self.caller_ua is None:
                self.caller_ua = user_agent
        else:
            party = "callee"
            if self.callee_ua is None:
                self.callee_ua = user_agent
        if self.cseq is None or cseq > self.cseq:
            log.debug("Received new SDP offer")
            self.streams[cseq] = new_streams = []
            if self.cseq is None:
                old_streams = []
            else:
                old_streams = self.streams[self.cseq]
            for media_type, media_ip, media_port, media_direction in media_list:
                stream = None
                for old_stream in old_streams:
                    old_remote = getattr(old_stream, party).remote_sdp
                    if old_stream.media_type == media_type and ((media_ip == "0.0.0.0" and old_remote[1] == media_port) or old_remote == (media_ip, media_port)):
                        stream = old_stream
                        stream.check_hold(party, media_direction, media_ip)
                        log.debug("Found matching existing stream: %s" % stream)
                        break
                if stream is None:
                    stream = MediaStream(self, media_type, media_ip, media_port, party, media_direction)
                    log.debug("Added new stream: %s" % stream)
                new_streams.append(stream)
            if self.previous_cseq is not None:
                for stream in self.streams[self.previous_cseq]:
                    if stream not in self.streams[self.cseq] + new_streams:
                        stream.cleanup()
            self.previous_cseq = self.cseq
            self.cseq = cseq
        elif self.cseq == cseq:
            log.debug("Received updated SDP answer")
            now = time()
            if self.start_time is None:
                self.start_time = now
            current_streams = self.streams[cseq]
            if len(media_list) < len(current_streams):
                for stream in current_streams[len(media_list):]:
                    log.debug("Stream rejected by not being included in the SDP answer: %s" % stream)
                    stream.cleanup("rejected")
                    if stream.start_time is None:
                        stream.start_time = now
            for stream, (media_type, media_ip, media_port, media_direction) in zip(current_streams, media_list):
                if stream.start_time is None:
                    stream.start_time = now
                if stream.media_type != media_type:
                    raise ValueError('Media types do not match: "%s" and "%s"' % (stream.media_type, media_type))
                if media_port == 0:
                    log.debug("Stream explicitly rejected: %s" % stream)
                    stream.cleanup("rejected")
                    continue
                stream.check_hold(party, media_direction, media_ip)
                party_info = getattr(stream, party)
                if party_info.remote_sdp is None or party_info.remote_sdp[0] == "0.0.0.0":
                    party_info.remote_sdp = (media_ip, media_port)
                    log.debug("Got initial answer from %s for stream: %s" % (party, stream))
                else:
                    if (media_ip == "0.0.0.0" and party_info.remote_sdp[1] != media_port) or party_info.remote_sdp != (media_ip, media_port):
                        stream.reset(party, media_ip, media_port)
                        log.debug("Updated %s for stream: %s" % (party, stream))
                    else:
                        log.debug("Unchanged stream: %s" % stream)
            if self.previous_cseq is not None:
                for stream in [stream for stream in self.streams[self.previous_cseq] if stream not in current_streams]:
                    log.debug("Removing old stream: %s" % stream)
                    stream.cleanup()
        else:
            log.debug("Received old CSeq %d:%d, ignoring" % cseq)

    def get_local_media(self, is_downstream, cseq, is_caller_cseq):
        if is_caller_cseq:
            pos = 0
        else:
            pos = 1
        cseq = max(key for key in self.streams.keys() if key[pos] == cseq)
        if is_downstream:
            retval = [(stream.status in ["active", "on hold"]) and stream.rtp.callee.local or (stream.rtp.callee.local[0], 0) for stream in self.streams[cseq]]
        else:
            retval = [(stream.status in ["active", "on hold"]) and stream.rtp.caller.local or (stream.rtp.caller.local[0], 0) for stream in self.streams[cseq]]
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
                active_streams.update([stream for stream in self.streams[cseq] if stream.is_alive])
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
    def statistics(self):
        all_streams = set(chain(*self.streams.itervalues()))
        media_types = set(s.media_type for s in all_streams)
        attributes = ('call_id', 'from_tag', 'from_uri', 'to_tag', 'to_uri', 'start_time', 'duration')
        stats = dict((name, getattr(self, name)) for name in attributes)
        stats['caller_ua'] = self.caller_ua or 'Unknown'
        stats['callee_ua'] = self.callee_ua or 'Unknown'
        stats['caller_bytes'] = dict((t, 0) for t in media_types)
        stats['callee_bytes'] = dict((t, 0) for t in media_types)
        stats['caller_packets'] = dict((t, 0) for t in media_types)
        stats['callee_packets'] = dict((t, 0) for t in media_types)
        stats['streams'] = streams = []
        stream_attributes = ('media_type', 'status', 'timeout_wait')
        for stream in sorted(all_streams, key=attrgetter('start_time')):
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
            info['caller_local'] = '%s:%d' % caller.local
            info['callee_local'] = '%s:%d' % callee.local
            info['caller_remote'] = caller.got_remote and ('%s:%d' % caller.remote) or 'Unknown'
            info['callee_remote'] = callee.got_remote and ('%s:%d' % callee.remote) or 'Unknown'
            info['caller_bytes'] = stream.rtp.caller_bytes + stream.rtcp.caller_bytes
            info['callee_bytes'] = stream.rtp.callee_bytes + stream.rtcp.callee_bytes
            info['caller_packets'] = stream.rtp.caller_packets + stream.rtcp.caller_packets
            info['callee_packets'] = stream.rtp.callee_packets + stream.rtcp.callee_packets
            stats['caller_bytes'][stream.media_type] += info['caller_bytes']
            stats['callee_bytes'][stream.media_type] += info['callee_bytes']
            stats['caller_packets'][stream.media_type] += info['caller_packets']
            stats['callee_packets'][stream.media_type] += info['callee_packets']
            streams.append(info)
        return stats


class SessionManager(Logger):
    implements(IReadDescriptor)

    def __init__(self, relay, start_port, end_port):
        self.relay = relay
        self.ports = deque((i, i+1) for i in xrange(start_port, end_port, 2))
        self.bad_ports = deque()
        self.sessions = {}
        self.watcher = _conntrack.ExpireWatcher()
        self.totals = {}
        self.bps_relayed = 0
        if Config.traffic_sampling_period > 0:
            self.speed_timer = reactor.callLater(Config.traffic_sampling_period, self._measure_speed)
        reactor.addReader(self)

    def _measure_speed(self):
        start_time = time()
        total_bytes = 0
        new_totals = dict((call_id, sum(sum(getattr(getattr(stream, substream), party) for party in ["caller_bytes", "callee_bytes"] for substream in ["rtp", "rtcp"]) for stream in set(chain(*session.streams.itervalues())))) for call_id, session in self.sessions.iteritems())
        for key, total in new_totals.iteritems():
            total_bytes += total - self.totals.get(key, 0)
        self.bps_relayed = 8 * total_bytes / Config.traffic_sampling_period
        self.totals = new_totals
        self.speed_timer = reactor.callLater(Config.traffic_sampling_period, self._measure_speed)
        us_taken = int((time() - start_time) * 1000000)
        if us_taken > 10000:
            log.warn("Aggregate speed calculation time exceeded 10ms: %d us for %d sessions" % (us_taken, len(self.sessions)))

    # implemented for IReadDescriptor
    def fileno(self):
        return self.watcher.fd

    def doRead(self):
        stream = self.watcher.read()
        if stream:
            stream.expired_func()

    def connectionLost(self, reason):
        reactor.removeReader(self)

    # port management
    def get_ports(self):
        if len(self.bad_ports) > len(self.ports):
            log.debug("Excessive amount of bad ports, doing cleanup")
            self.ports.extend(self.bad_ports)
            self.bad_ports = deque()
        return self.ports.popleft()

    def set_bad_ports(self, ports):
        self.bad_ports.append(ports)

    def free_ports(self, ports):
        self.ports.append(ports)

    # called by higher level
    def _find_session_key(self, call_id, from_tag, kw_rest):
        key_from = (call_id, from_tag)
        if key_from in self.sessions:
            return key_from
        to_tag = kw_rest.get("to_tag")
        if to_tag:
            key_to = (call_id, to_tag)
            if key_to in self.sessions:
                return key_to

    def update_session(self, dispatcher, call_id, from_tag, from_uri, to_uri, cseq, user_agent, media, type, **kw_rest):
        to_tag = kw_rest.get("to_tag")
        key = self._find_session_key(call_id, from_tag, kw_rest)
        if key:
            session = self.sessions[key]
            log.debug("updating existing session %s" % session)
            is_downstream = (session.from_tag != from_tag) ^ (type == "request")
            is_caller_cseq = (session.from_tag == from_tag)
            session.update_media(cseq, to_tag, user_agent, media, is_downstream, is_caller_cseq)
        else:
            if not self.relay.add_session(dispatcher):
                log.debug("cannot add new session, MediaProxy relay is shutting down")
                return None
            is_downstream = type == "request"
            is_caller_cseq = True
            session = self.sessions[(call_id, from_tag)] = Session(self, dispatcher, call_id, from_tag, from_uri, to_tag, to_uri, cseq, user_agent, media, is_downstream, is_caller_cseq)
            log.debug("created new session %s" % session)
        retval = session.get_local_media(is_downstream, cseq, is_caller_cseq)
        for index, (media_type, media_ip, media_port, media_direction) in enumerate(media):
            if media_ip == "0.0.0.0":
                retval[index] = ("0.0.0.0", retval[index][1])
        return retval

    def remove_session(self, call_id, from_tag, **kw_rest):
        key = self._find_session_key(call_id, from_tag, kw_rest)
        try:
            session = self.sessions[key]
        except KeyError:
            log.warn("The dispatcher tried to remove a session which is no longer present on the relay")
            return None
        log.debug("removing session %s" % session)
        session.cleanup()
        dispatcher = session.dispatcher
        del self.sessions[key]
        reactor.callLater(0, self.relay.remove_session, dispatcher)
        return session

    def session_expired(self, call_id, from_tag):
        key = (call_id, from_tag)
        try:
            session = self.sessions[key]
        except KeyError:
            log.warn("A session expired that was no longer present on the relay")
            return
        log.debug("expired session %s" % session)
        dispatcher = session.dispatcher
        session.cleanup()
        del self.sessions[key]
        self.relay.session_expired(session)
        self.relay.remove_session(dispatcher)

    def get_statistics(self):
        return [session.statistics for session in self.sessions.itervalues()]

    def get_stream_count(self):
        stream_count = {}
        for session in self.sessions.itervalues():
            for stream in set(chain(*session.streams.itervalues())):
                if stream.is_alive:
                    stream_count[stream.media_type] = stream_count.get(stream.media_type, 0) + 1
        return stream_count

    def cleanup(self):
        if Config.traffic_sampling_period > 0:
            if self.speed_timer.active():
                self.speed_timer.cancel()
        for key in self.sessions.keys():
            self.session_expired(*key)
