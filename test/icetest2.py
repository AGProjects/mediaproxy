#!/usr/bin/env python

# Copyright (C) 2009 AG Projects
#

"""
This test simulates a call flow with ICE where the relay is selected as a candidate:
   - The caller sends an INVITE
   - the callee sends a 200 OK
   - Both parties will send probing STUN requests for a few seconds
   - Both parties will stop the probes and start sending media through the relay
     (Note that a re-INVITE will be sent, this is due to a limitatin in the test framework)
   - After 5 seconds, the caller will send a BYE
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
    defer.addCallback(do_media, callee_addr, protocol, session, caller_media, callee_media)
    return defer

def do_media((caller_ip, caller_ports), (callee_ip, callee_ports), protocol, session, caller_media, callee_media):
    print "starting STUN probes for both parties"
    session.caller.start_media(caller_ip, caller_ports, send_stun=True)
    session.callee.start_media(callee_ip, callee_ports, send_stun=True)
    defer = DeferredList([caller_media, callee_media])
    defer.addCallback(wait, protocol, session)
    return defer

def wait(result, protocol, session):
    print "got STUN, waiting 5 seconds"
    defer = Deferred()
    defer.addCallback(stop_media, protocol, session)
    reactor.callLater(5, defer.callback, None)
    return defer

def stop_media(result, protocol, session):
    print "stopping STUN probes"
    defer = DeferredList([session.caller.stop_media(), session.callee.stop_media()])
    defer.addCallback(change_callee, protocol, session)
    return defer

def change_callee(result, protocol, session):
    print "sending new update for callee"
    caller_media = session.caller.set_media([("audio", 40000, "sendrecv", {"ice":"yes"})])
    callee_media = session.callee.set_media([("audio", 50000, "sendrecv", {"ice":"yes"})])
    media_defer = DeferredList([caller_media, callee_media])
    defer = session.do_update(protocol, "callee", "request", False)
    defer.addCallback(change_caller, protocol, session, media_defer)
    return defer

def change_caller((caller_ip, caller_ports), protocol, session, media_defer):
    print "sending new update for caller"
    defer = session.do_update(protocol, "caller", "reply", True)
    defer.addCallback(start_new_media, protocol, session, media_defer, caller_ip, caller_ports)
    return defer

def start_new_media((callee_ip, callee_ports), protocol, session, media_defer, caller_ip, caller_ports):
    print "starting media"
    session.caller.start_media(caller_ip, caller_ports)
    session.callee.start_media(callee_ip, callee_ports)
    media_defer.addCallback(wait2, protocol, session)
    return media_defer

def wait2(result, protocol, session):
    print "got media, waiting 5 seconds"
    defer = Deferred()
    defer.addCallback(kthxbye, protocol, session)
    reactor.callLater(5, defer.callback, None)
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
    caller_media = caller.set_media([("audio", 40000, "sendrecv", {"ice":"yes"})])
    callee = Endpoint("Bob <bob@example.com>", "Callee UA", False)
    callee_media = callee.set_media([("audio", 50000, "sendrecv", {"ice":"yes"})])
    session = Session(caller, callee)
    connector, defer = connect_to_dispatcher()
    defer.addCallback(caller_update, session, caller_media, callee_media)
    defer.addCallback(disconnect, connector)
    defer.addErrback(catch_all_err)
    reactor.run()
