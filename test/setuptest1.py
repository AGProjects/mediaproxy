#!/usr/bin/env python

# Copyright (C) 2008 AG Projects
#

"""
This test scenario simulates the caller sending an INVITE, nothing is
received in return. The relay should discard the session after a while.
"""

from common import *

def caller_update(protocol, session):
    print "doing update for caller"
    return session.do_update(protocol, "caller", "request", False)

def disconnect(result, connector):
    print "disconnecting"
    connector.disconnect()
    reactor.callLater(1, reactor.stop)

def catch_all_err(failure):
    print failure

if __name__ == "__main__":
    caller = Endpoint("Alice <alice@example.com>", "Caller UA", True)
    caller.set_media([("audio", 40000, "sendrecv", {})])
    callee = Endpoint("Bob <bob@example.com>", "Callee UA", False)
    callee.set_media([("audio", 50000, "sendrecv", {})])
    session = Session(caller, callee)
    connector, defer = connect_to_dispatcher()
    defer.addCallback(caller_update, session)
    defer.addCallback(disconnect, connector)
    defer.addErrback(catch_all_err)
    reactor.run()
