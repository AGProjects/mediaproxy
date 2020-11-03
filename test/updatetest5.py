#!/usr/bin/python3

# Copyright (C) 2008 AG Projects
#

"""
This test simulates a call setup with an updated reply from the callee:
   - The caller sends an INVITE
   - The callee replies with a provisional response containg SDP e.g. 183
   - Both parties start sending media
   - Media flows for 5 seconds
   - Media stops
   - The callee sends another 183 with new port and to-tag (e.g. when the first PSTN gateway failed)
   - Both parties start sending media
   - Media flows for 5 seconds
   - Media stops
   - The callee sends a 200 OK with a new port
   - Media flows again for 5 seconds
   - The caller sends a BYE
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


def do_media(caller_addr, callee_addr, protocol, session, caller_media, callee_media):
    (caller_ip, caller_ports) = caller_addr
    (callee_ip, callee_ports) = callee_addr
    print('starting media for both parties')
    session.caller.start_media(caller_ip, caller_ports)
    session.callee.start_media(callee_ip, callee_ports)
    defer = DeferredList([caller_media, callee_media])
    defer.addCallback(wait, protocol, session, callee_ip, callee_ports)
    return defer


def wait(result, protocol, session, callee_ip, callee_ports):
    print('got media, waiting 5 seconds')
    defer = Deferred()
    defer.addCallback(stop_media, protocol, session, callee_ip, callee_ports)
    reactor.callLater(5, defer.callback, None)
    return defer


def stop_media(result, protocol, session, callee_ip, callee_ports):
    print('stopping media')
    defer = DeferredList([session.caller.stop_media(), session.callee.stop_media()])
    defer.addCallback(change_callee_prov, protocol, session, callee_ip, callee_ports)
    return defer


def change_callee_prov(result, protocol, session, callee_ip, callee_ports):
    print('sending new provisional update for callee')
    session.callee.tag = 'newtotag'
    caller_media = session.caller.set_media([('audio', 40000, 'sendrecv', {})])
    callee_media = session.callee.set_media([('audio', 30010, 'sendrecv', {})])
    media_defer = DeferredList([caller_media, callee_media])
    defer = session.do_update(protocol, 'callee', 'reply', False)
    defer.addCallback(start_new_media_prov, protocol, session, media_defer, callee_ip, callee_ports)
    return defer


def start_new_media_prov(caller_addr, protocol, session, media_defer, callee_ip, callee_ports):
    (caller_ip, caller_ports) = caller_addr
    print('starting new media')
    session.caller.start_media(caller_ip, caller_ports)
    session.callee.start_media(callee_ip, callee_ports)
    media_defer.addCallback(wait2, protocol, session, callee_ip, callee_ports)
    return media_defer


def wait2(result, protocol, session, callee_ip, callee_ports):
    print('got new media, waiting 5 seconds')
    defer = Deferred()
    defer.addCallback(stop_media_prov, protocol, session, callee_ip, callee_ports)
    reactor.callLater(5, defer.callback, None)
    return defer


def stop_media_prov(result, protocol, session, callee_ip, callee_ports):
    print('stopping media')
    defer = DeferredList([session.caller.stop_media(), session.callee.stop_media()])
    defer.addCallback(change_callee, protocol, session, callee_ip, callee_ports)
    return defer


def change_callee(result, protocol, session, callee_ip, callee_ports):
    print('sending new update for callee')
    caller_media = session.caller.set_media([('audio', 40000, 'sendrecv', {})])
    callee_media = session.callee.set_media([('audio', 30020, 'sendrecv', {})])
    media_defer = DeferredList([caller_media, callee_media])
    defer = session.do_update(protocol, 'callee', 'reply', True)
    defer.addCallback(start_new_media, protocol, session, media_defer, callee_ip, callee_ports)
    return defer


def start_new_media(caller_addr, protocol, session, media_defer, callee_ip, callee_ports):
    (caller_ip, caller_ports) = caller_addr
    print('starting new media')
    session.caller.start_media(caller_ip, caller_ports)
    session.callee.start_media(callee_ip, callee_ports)
    media_defer.addCallback(wait3, protocol, session)
    return media_defer


def wait3(result, protocol, session):
    print('got new media, waiting 5 seconds')
    defer = Deferred()
    defer.addCallback(kthxbye, protocol, session)
    reactor.callLater(5, defer.callback, None)
    return defer


def kthxbye(result, protocol, session):
    print('sending remove')
    return session.do_remove(protocol, 'caller')


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
