#!/usr/bin/env python

# Copyright (C) 2008 AG Projects
#

"""
This test simulates a session in which the caller proposes 3 streams in the
INTIVE and the callee rejects two of these.
   - The caller sends an INVITE with 1 video stream and 2 audio streams
   - the callee sends a 200 OK with the ports for two of the streams set to 0
   - Both parties start sending media
   - Media flows for 5 seconds
   - The callee sends a BYE
"""

from common import *

def caller_update(protocol, session, caller_media, callee_media):
    print "doing update for caller"
    defer = session.do_update(protocol, "caller", "request", False)
    defer.addCallback(callee_update, protocol, session, caller_media, callee_media)
    return defer

def callee_update(callee_addr, protocol, session, caller_media, callee_media):
    print "doing update for callee"
    defer = session.do_update(protocol, "callee", "reply", True)
    defer.addCallback(change_caller1, callee_addr, protocol, session, caller_media, callee_media)
    return defer

def change_caller1(caller_addr, callee_addr, protocol, session, caller_media, callee_media):
    print "stopping media for caller"
    defer = session.caller.stop_media()
    defer.addCallback(change_caller2, caller_addr, callee_addr, protocol, session, callee_media)
    return defer

def change_caller2(result, caller_addr, callee_addr, protocol, session, callee_media):
    print "setting new media for caller"
    caller_media = caller.set_media([("audio", 0, "sendrecv"), ("video", 0, "sendrecv"), ("audio", 40020, "sendrecv")])
    return do_media(caller_addr, callee_addr, protocol, session, caller_media, callee_media)

def do_media((caller_ip, caller_ports), (callee_ip, callee_ports), protocol, session, caller_media, callee_media):
    print "starting media for both parties"
    session.caller.start_media(caller_ip, caller_ports)
    session.callee.start_media(callee_ip, callee_ports)
    defer = DeferredList([caller_media, callee_media])
    defer.addCallback(wait, protocol, session)
    return defer

def wait(result, protocol, session):
    print "got media, waiting 5 seconds"
    defer = Deferred()
    defer.addCallback(kthxbye, protocol, session)
    reactor.callLater(5, defer.callback, None)
    return defer

def kthxbye(result, protocol, session):
    print "sending remove"
    return session.do_remove(protocol, "callee")

def disconnect(result, connector):
    print "disconnecting"
    connector.disconnect()
    reactor.callLater(1, reactor.stop)

def catch_all_err(failure):
    print failure

if __name__ == "__main__":
    caller = Endpoint("Alice <alice@example.com>", "Caller UA", True)
    caller_media = caller.set_media([("audio", 40000, "sendrecv"), ("video", 40010, "sendrecv"), ("audio", 40020, "sendrecv")])
    callee = Endpoint("Bob <bob@example.com>", "Callee UA", False)
    callee_media = callee.set_media([("audio", 0, "sendrecv"), ("video", 0, "sendrecv"), ("audio", 50020, "sendrecv")])
    session = Session(caller, callee)
    connector, defer = connect_to_dispatcher()
    defer.addCallback(caller_update, session, caller_media, callee_media)
    defer.addCallback(disconnect, connector)
    defer.addErrback(catch_all_err)
    reactor.run()
