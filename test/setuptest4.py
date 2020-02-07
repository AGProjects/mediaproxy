#!/usr/bin/python2

# Copyright (C) 2008 AG Projects
#

"""
This test simulates a normal call flow, with an added ACK confirming
the SDP:
   - The caller sends an INVITE
   - the callee sends a 200 OK
   - Both parties will start sending media
   - the caller sends an ACK with SDP
   - Media will flow for 5 seconds
   - The callee will send a BYE
"""

from common import *


def caller_update(protocol, session, caller_media, callee_media):
    print('doing update for caller')
    defer = session.do_update(protocol, 'caller', 'request', False)
    defer.addCallback(callee_update, protocol, session, caller_media, callee_media)
    return defer


def callee_update(callee_addr, protocol, session, caller_media, callee_media):
    print('doing update for callee')
    defer = session.do_update(protocol, 'callee', 'reply', False)
    defer.addCallback(do_media, callee_addr, protocol, session, caller_media, callee_media)
    return defer


def do_media((caller_ip, caller_ports), (callee_ip, callee_ports), protocol, session, caller_media, callee_media):
    print('starting media for both parties')
    session.caller.start_media(caller_ip, caller_ports)
    session.callee.start_media(callee_ip, callee_ports)
    defer = DeferredList([caller_media, callee_media])
    defer.addCallback(caller_ack, protocol, session, callee_ip, callee_ports)
    return defer


def caller_ack(result, protocol, session, callee_ip, callee_ports):
    print('got media, doing ACK for caller')
    defer = session.do_update(protocol, 'caller', 'request', True)
    defer.addCallback(wait, protocol, session, callee_ip, callee_ports)
    return defer


def wait((callee_ack_ip, callee_ack_ports), protocol, session, callee_ip, callee_ports):
    print('waiting 5 seconds')
    assert (callee_ack_ip == callee_ip)
    assert (callee_ack_ports == callee_ports)
    defer = Deferred()
    defer.addCallback(kthxbye, protocol, session)
    reactor.callLater(5, defer.callback, None)
    return defer


def kthxbye(result, protocol, session):
    print('sending remove')
    return session.do_remove(protocol, 'callee')


def disconnect(result, connector):
    print('disconnecting')
    connector.disconnect()
    reactor.callLater(1, reactor.stop)


def catch_all_err(failure):
    print(failure)


if __name__ == '__main__':
    caller = Endpoint('Alice <alice@example.com>', 'Caller UA', True)
    caller_media = caller.set_media([('audio', 40000, 'sendrecv', {})])
    callee = Endpoint('Bob <bob@example.com>', 'Callee UA', False)
    callee_media = callee.set_media([('audio', 30000, 'sendrecv', {})])
    session = Session(caller, callee)
    connector, defer = connect_to_dispatcher()
    defer.addCallback(caller_update, session, caller_media, callee_media)
    defer.addCallback(disconnect, connector)
    defer.addErrback(catch_all_err)
    reactor.run()
