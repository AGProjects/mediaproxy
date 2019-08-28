#!/usr/bin/env python

# Copyright (C) 2008 AG Projects
#

"""
This test simulates a session with audio and video media flowing, after which
the callee removes the video stream and only audio flows. After a while, the
video stream is introduced back and both audio and video flow for a while:
  - caller sends INVITE, callee sends 200 ok
  - audio and video media flows for 15 seconds
  - callee proposes to keep only the audio stream using a re-INVITE, caller
    sends OK
  - audio media flows for 15 seconds
  - callee proposes to reintroduce a video stream using a re-INVITE, caller
    sends OK
  - audio and video media flows for 15 seconds
  - caller sends BYE
"""

from common import *


def caller_update(protocol, session, caller_media, callee_media):
    print('doing update for caller')
    defer = session.do_update(protocol, 'caller', 'request', False)
    defer.addCallback(callee_update, protocol, session, caller_media, callee_media)
    return defer


def callee_update(callee_addr, protocol, session, caller_media, callee_media):
    print('doing update for callee')
    defer = session.do_update(protocol, 'callee', 'reply', True)
    defer.addCallback(do_media, callee_addr, protocol, session, caller_media, callee_media)
    return defer


def do_media((caller_ip, caller_ports), (callee_ip, callee_ports), protocol, session, caller_media, callee_media):
    print('starting media for both parties')
    session.caller.start_media(caller_ip, caller_ports)
    session.callee.start_media(callee_ip, callee_ports)
    defer = DeferredList([caller_media, callee_media])
    defer.addCallback(wait, protocol, session)
    return defer


def wait(result, protocol, session):
    print('got media, waiting 15 seconds')
    defer = Deferred()
    defer.addCallback(stop_media, protocol, session)
    reactor.callLater(15, defer.callback, None)
    return defer


def stop_media(result, protocol, session):
    print('stopping media')
    defer = DeferredList([session.caller.stop_media(), session.callee.stop_media()])
    defer.addCallback(change_callee, protocol, session)
    return defer


def change_callee(result, protocol, session):
    print('sending new update for callee')
    caller_media = session.caller.set_media([('audio', 40000, 'sendrecv', {}), ('video', 0, 'sendrecv', {})])
    callee_media = session.callee.set_media([('audio', 50000, 'sendrecv', {}), ('video', 0, 'sendrecv', {})])
    media_defer = DeferredList([caller_media, callee_media])
    defer = session.do_update(protocol, 'callee', 'request', False)
    defer.addCallback(change_caller, protocol, session, media_defer)
    return defer


def change_caller((caller_ip, caller_ports), protocol, session, media_defer):
    print('sending new update for caller')
    defer = session.do_update(protocol, 'caller', 'reply', True)
    defer.addCallback(start_new_media, protocol, session, media_defer, caller_ip, caller_ports)
    return defer


def start_new_media((callee_ip, callee_ports), protocol, session, media_defer, caller_ip, caller_ports):
    print('starting new media')
    session.caller.start_media(caller_ip, caller_ports)
    session.callee.start_media(callee_ip, callee_ports)
    media_defer.addCallback(wait2, protocol, session)
    return media_defer


def wait2(result, protocol, session):
    print('got new media, waiting 15 seconds')
    defer = Deferred()
    defer.addCallback(stop_media2, protocol, session)
    reactor.callLater(15, defer.callback, None)
    return defer


def stop_media2(result, protocol, session):
    print('stopping media')
    defer = DeferredList([session.caller.stop_media(), session.callee.stop_media()])
    defer.addCallback(change_callee2, protocol, session)
    return defer


def change_callee2(result, protocol, session):
    print('sending new update for callee')
    caller_media = session.caller.set_media([('audio', 40000, 'sendrecv', {}), ('video', 40010, 'sendrecv', {})])
    callee_media = session.callee.set_media([('audio', 50000, 'sendrecv', {}), ('video', 50010, 'sendrecv', {})])
    media_defer = DeferredList([caller_media, callee_media])
    defer = session.do_update(protocol, 'callee', 'request', False)
    defer.addCallback(change_caller2, protocol, session, media_defer)
    return defer


def change_caller2((caller_ip, caller_ports), protocol, session, media_defer):
    print('sending new update for caller')
    defer = session.do_update(protocol, 'caller', 'reply', True)
    defer.addCallback(start_new_media2, protocol, session, media_defer, caller_ip, caller_ports)
    return defer


def start_new_media2((callee_ip, callee_ports), protocol, session, media_defer, caller_ip, caller_ports):
    print('starting new media')
    session.caller.start_media(caller_ip, caller_ports)
    session.callee.start_media(callee_ip, callee_ports)
    media_defer.addCallback(wait3, protocol, session)
    return media_defer


def wait3(result, protocol, session):
    print('got new media, waiting 15 seconds')
    defer = Deferred()
    defer.addCallback(kthxbye, protocol, session)
    reactor.callLater(15, defer.callback, None)
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
    caller_media = caller.set_media([('audio', 40000, 'sendrecv', {}), ('video', 40010, 'sendrecv', {})])
    callee = Endpoint('Bob <bob@example.com>', 'Callee UA', False)
    callee_media = callee.set_media([('audio', 50000, 'sendrecv', {}), ('video', 50010, 'sendrecv', {})])
    session = Session(caller, callee)
    connector, defer = connect_to_dispatcher()
    defer.addCallback(caller_update, session, caller_media, callee_media)
    defer.addCallback(disconnect, connector)
    defer.addErrback(catch_all_err)
    reactor.run()
