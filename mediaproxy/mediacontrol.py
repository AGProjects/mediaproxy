#
# Copyright (C) 2008 AG Projects
# Author: Ruud Klaver <ruud@ag-projects.com>
#

from time import time
from collections import deque

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

UDP_TIMEOUT_FILE = "/proc/sys/net/ipv4/netfilter/ip_conntrack_udp_timeout_stream"

rtp_payloads = {
     0: "G711u", 1: "1016",  2: "G721",  3: "GSM",  4: "G723",  5: "DVI4", 6: "DVI4",
     7: "LPC",   8: "G711a", 9: "G722", 10: "L16", 11: "L16",  14: "MPA", 15: "G728",
    18: "G729", 25: "CelB", 26: "JPEG", 28: "nv",  31: "H261", 32: "MPV", 33: "MP2T",
    34: "H263"
}

class Config(ConfigSection):
    stream_timeout = 90

configuration = ConfigFile(configuration_filename)
configuration.read_settings("Relay", Config)

class StreamListenerProtocol(DatagramProtocol):
    noisy = False

    def __init__(self):
        self.cb_func = None

    def datagramReceived(self, data, (host, port)):
        if self.cb_func is not None:
            self.cb_func(host, port, data)


class MediaSubParty(object):

    def __init__(self, substream, listener):
        self.substream = substream
        self.listener = listener
        self.listener.protocol.cb_func = self.got_data
        self.inhibitor = None
        self.remote = None
        host = self.listener.protocol.transport.getHost()
        self.local = (host.host, host.port)
        self.bytes = 0
        self.bytes_rtcp = 0
        self.packets = 0
        self.packets_rtcp = 0
        self.timer = None
        self.codec = "Unknown"
        self.reset(True)

    def reset(self, expire):
        self.start_block()
        self.got_remote = False
        if self.timer and self.timer.active():
            self.timer.cancel()
        if expire:
            self.timer = reactor.callLater(Config.stream_timeout, self.substream.expired, "no traffic timeout", Config.stream_timeout)
        else:
            self.timer = None
            self.remote = None

    def after_hold(self):
        if self.timer and self.timer.active():
            self.timer.cancel()
        if not self.got_remote:
            self.timer = reactor.callLater(Config.stream_timeout, self.substream.expired, "no traffic timeout", Config.stream_timeout)

    def start_block(self):
        if self.inhibitor is None:
            self.inhibitor = _conntrack.Inhibitor(self.local[1])

    def stop_block(self):
        self.inhibitor = None

    def got_data(self, host, port, data):
        if not self.got_remote:
            if (host, port) == self.remote:
                return
            if self.timer:
                self.timer.cancel()
                self.timer = None
            if self.codec == "Unknown" and self.substream is self.substream.stream.rtp:
                try:
                    pt = ord(data[2]) & 127
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
            pass # what to do?

    def cleanup(self):
        if self.timer and self.timer.active():
            self.timer.cancel()
        self.timer = None
        self.stop_block()
        self.local = (self.local[0], 0)
        self.listener.protocol.cb_func = None
        self.substream = None


class MediaSubStream(object):

    def __init__(self, stream, listener_caller, listener_callee):
        self.stream = stream
        self.forwarding_rule = None
        self.caller = MediaSubParty(self, listener_caller)
        self.callee = MediaSubParty(self, listener_callee)

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
            self.callee.start_block()
        else:
            self.callee.reset(True)
            self.caller.start_block()
        self._stop_relaying()

    def check_create_conntrack(self):
        log.debug("Got traffic information for stream: %s" % self.stream)
        if self.caller.got_remote and self.callee.got_remote:
            self.forwarding_rule = _conntrack.ForwardingRule(self.caller.remote, self.caller.local, self.callee.remote, self.callee.local, self.stream.session.mark)
            self.forwarding_rule.expired_func = self.conntrack_expired
            self.caller.stop_block()
            self.callee.stop_block()

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
        self.remote_sdp = None
        self.is_on_hold = False
        while True:
            self.listener_rtp = None
            self.ports = port_rtp, port_rtcp = self.manager.get_ports()
            try:
                self.listener_rtp = reactor.listenUDP(port_rtp, StreamListenerProtocol(), interface=default_host_ip)
                self.listener_rtcp = reactor.listenUDP(port_rtcp, StreamListenerProtocol(), interface=default_host_ip)
            except CannotListenError:
                if self.listener_rtp is not None:
                    self.listener_rtp.stopListening()
                self.manager.set_bad_ports(self.ports)
                log.warn("Cannot use port pair %d/%d" % self.ports)
            else:
                break

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
        self.start_time = time()
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
                    subparty.after_hold()

    def reset(self, party, media_ip, media_port):
        self.rtp.reset(party)
        self.rtcp.reset(party)
        getattr(self, party).remote_sdp = (media_ip, media_port)

    def substream_expired(self, substream, reason, timeout_wait):
        # This will cause any re-occuronce of the same traffic to be forwarded again
        if substream is self.rtcp or self.is_on_hold:
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
            if self.start_time is None:
                self.start_time = time()
            current_streams = self.streams[cseq]
            if len(media_list) != len(current_streams):
                raise Exception # TODO: elaborate
            for stream, (media_type, media_ip, media_port, media_direction) in zip(current_streams, media_list):
                if stream.media_type != media_type:
                    raise Exception # TODO: elaborate
                if media_port == 0:
                    log.debug("Stream rejected: %s" % stream)
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
            log.debug("Received old CSeq %d, ignoring" % cseq)

    def get_local_media(self, is_downstream, cseq, is_caller_cseq):
        if is_caller_cseq:
            pos = 0
        else:
            pos = 1
        cseq = max(key for key in self.streams.keys() if key[pos] == cseq)
        if is_downstream:
            retval = [stream.rtp.callee.local for stream in self.streams[cseq]]
        else:
            retval = [stream.rtp.caller.local for stream in self.streams[cseq]]
        return retval

    def cleanup(self):
        self.end_time = time()
        for cseq in [self.previous_cseq, self.cseq]:
            if cseq is not None:
                for stream in self.streams[cseq]:
                    stream.cleanup()

    def get_totals(self, party, stat_type):
        retval = {}
        for stream in set(sum(self.streams.values(), [])):
            retval[stream.media_type] = retval.get(stream.media_type, 0) + getattr(getattr(stream.rtp, party), stat_type) + getattr(getattr(stream.rtcp, party), stat_type)
        return retval

    def stream_expired(self, stream):
        active_streams = set()
        for cseq in [self.previous_cseq, self.cseq]:
            if cseq is not None:
                active_streams.update([stream for stream in self.streams[cseq] if stream.is_alive])
        if len(active_streams) == 0:
            self.manager.session_expired(self.call_id, self.from_tag)

    @property
    def duration(self):
        if self.start_time is not None and self.end_time is not None:
            return int(self.end_time - self.start_time)
        else:
            return 0

    @property
    def statistics(self):
        stats = {}
        for party in ["caller", "callee"]:
            for stat_type in ["bytes", "packets"]:
                stats["%s_%s" % (party, stat_type)] = self.get_totals(party, stat_type)
        for attr in ["call_id", "from_tag", "from_uri", "to_tag", "to_uri", "duration"]:
            stats[attr] = getattr(self, attr)
        for attr in ["caller_ua", "callee_ua"]:
            ua = getattr(self, attr)
            if ua is None:
                stats[attr] = "Unknown"
            else:
                stats[attr] = ua
        streams = stats["streams"] = []
        for stream in sorted(set(sum(self.streams.values(), [])), key=lambda x: getattr(x, "start_time")):
            stream_info = {}
            if self.start_time is None:
                stream_info["start_time"] = stream_info["end_time"] = 0
            else:
                stream_info["start_time"] = max(int(stream.start_time - self.start_time), 0)
                stream_info["end_time"] = min(int(stream.end_time - self.start_time), stats["duration"])
            stream_info["media_type"] = stream.media_type
            stream_info["caller_codec"] = stream.rtp.caller.codec
            stream_info["callee_codec"] = stream.rtp.callee.codec
            stream_info["status"] = stream.status
            stream_info["timeout_wait"] = stream.timeout_wait
            streams.append(stream_info)
        return stats


class SessionManager(Logger):
    implements(IReadDescriptor)

    def __init__(self, relay, start_port, end_port):
        self.relay = relay
        self.ports = deque((i, i+1) for i in xrange(start_port, end_port, 2))
        self.bad_ports = deque()
        self.sessions = {}
        self.watcher = _conntrack.ExpireWatcher()
        reactor.addReader(self)

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
        session = self.sessions[key]
        log.debug("removing session %s" % session)
        session.cleanup()
        dispatcher = session.dispatcher
        del self.sessions[key]
        reactor.callLater(0, self.relay.remove_session, dispatcher)
        return session

    def session_expired(self, call_id, from_tag):
        key = (call_id, from_tag)
        session = self.sessions[key]
        log.debug("expired session %s" % session)
        dispatcher = session.dispatcher
        session.cleanup()
        del self.sessions[key]
        self.relay.session_expired(session)
        self.relay.remove_session(dispatcher)

    def cleanup(self):
        for key in self.sessions.keys():
            self.session_expired(*key)
