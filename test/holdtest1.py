#!/usr/bin/env python

# Copyright (C) 2008 AG Projects
#

"""
This test simulates a session that starts with 1 audio stream, then gets put
on hold by the caller for 5 minutes, the gets taken out of hold again. This
test uses the newer "sendonly" direction attribute to indicate hold status.
"""

from common import *

def phase1(protocol, session):
    print "setting up audio stream"
    caller_media = session.caller.set_media([("audio", 40000, "sendrecv", "")])
    callee_media = session.callee.set_media([("audio", 50000, "sendrecv", "")])
    media_defer = DeferredList([caller_media, callee_media])
    defer = succeed(None)
    defer.addCallback(caller_update, protocol, session, media_defer, phase2)
    return defer

def phase2(result, protocol, session):
    print "setting stream on hold"
    session.caller.set_media([("audio", 40000, "sendonly", "")])
    session.callee.set_media([("audio", 50000, "recvonly", "")])
    defer = session.do_update(protocol, "caller", "request", False)
    defer.addCallback(callee_update_hold, protocol, session)
    return defer

def callee_update_hold(result, protocol, session):
    print "updating hold for callee"
    defer = session.do_update(protocol, "callee", "reply", True)
    defer.addCallback(wait_hold, protocol, session)
    return defer

def wait_hold(result, protocol, session):
    print "on hold, waiting 5 minutes..."
    defer = Deferred()
    defer.addCallback(stop_media_hold, protocol, session)
    reactor.callLater(300, defer.callback, None)
    return defer

def stop_media_hold(result, protocol, session):
    print "stopping media for hold"
    defer = DeferredList([session.caller.stop_media(), session.callee.stop_media()])
    defer.addCallback(phase3, protocol, session)
    return defer

def phase3(result, protocol, session):
    print "continuing audio stream"
    caller_media = session.caller.set_media([("audio", 40000, "sendrecv", "")])
    callee_media = session.callee.set_media([("audio", 50000, "sendrecv", "")])
    media_defer = DeferredList([caller_media, callee_media])
    defer = succeed(None)
    defer.addCallback(caller_update, protocol, session, media_defer, kthxbye)
    return defer

def caller_update(result, protocol, session, media_defer, do_after):
    print "doing update for caller"
    defer = session.do_update(protocol, "caller", "request", False)
    defer.addCallback(callee_update, protocol, session, media_defer, do_after)
    return defer

def callee_update(callee_addr, protocol, session, media_defer, do_after):
    print "doing update for callee"
    defer = session.do_update(protocol, "callee", "reply", True)
    defer.addCallback(do_media, callee_addr, protocol, session, media_defer, do_after)
    return defer

def do_media((caller_ip, caller_ports), (callee_ip, callee_ports), protocol, session, media_defer, do_after):
    print "starting media for both parties"
    session.caller.start_media(caller_ip, caller_ports)
    session.callee.start_media(callee_ip, callee_ports)
    media_defer.addCallback(wait, protocol, session, do_after)
    return media_defer

def wait(result, protocol, session, do_after):
    print "got media, waiting 5 seconds"
    defer = Deferred()
    defer.addCallback(stop_media, protocol, session, do_after)
    reactor.callLater(5, defer.callback, None)
    return defer

def stop_media(result, protocol, session, do_after):
    print "stopping media"
    defer = DeferredList([session.caller.stop_media(), session.callee.stop_media()])
    defer.addCallback(do_after, protocol, session)
    return defer

def kthxbye(result, protocol, session):
    print "sending remove"
    return session.do_remove(protocol, "caller")

def disconnect(result, connector):
    print "disconnecting"
    connector.disconnect()
    reactor.callLater(1, reactor.stop)

def catch_all_err(failure):
    print failure

if __name__ == "__main__":
    caller = Endpoint("Alice <alice@example.com>", "Caller UA", True)
    callee = Endpoint("Bob <bob@example.com>", "Callee UA", False)
    session = Session(caller, callee)
    connector, defer = connect_to_dispatcher()
    defer.addCallback(phase1, session)
    defer.addCallback(disconnect, connector)
    defer.addErrback(catch_all_err)
    reactor.run()
