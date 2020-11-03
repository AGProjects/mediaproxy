#!/usr/bin/python3

# Copyright (C) 2009 AG Projects
#

"""
This test simulates a call flow with ICE where the relay is NOT selected as a candidate:
   - The caller sends an INVITE
   - the callee sends a 200 OK
   - Both parties will send probing STUN requests for a few seconds
   - Both parties will stop the probes and not send media through the relay
   - After 4 minutes, the callee will send a BYE
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
    defer.addCallback(do_stun, callee_addr, protocol, session, caller_media, callee_media)
    return defer


def do_stun(caller_addr, callee_addr, protocol, session, caller_media, callee_media):
    (caller_ip, caller_ports) = caller_addr
    (callee_ip, callee_ports) = callee_addr
    print('starting STUN probes for both parties')
    session.caller.start_media(caller_ip, caller_ports, send_stun=True)
    session.callee.start_media(callee_ip, callee_ports, send_stun=True)
    defer = DeferredList([caller_media, callee_media])
    defer.addCallback(wait_stun, session, protocol)
    return defer


def wait_stun(result, session, protocol):
    print('got STUN probes, waiting 3 seconds')
    defer = Deferred()
    defer.addCallback(stop_stun_caller, session, protocol)
    reactor.callLater(3, defer.callback, None)
    return defer


def stop_stun_caller(result, session, protocol):
    print('stopping STUN probes for caller')
    defer = session.caller.stop_media()
    defer.addCallback(stop_stun_callee, session, protocol)
    return defer


def stop_stun_callee(result, session, protocol):
    print('stopping STUN probes for callee')
    defer = session.callee.stop_media()
    defer.addCallback(wait_end, session, protocol)
    return defer


def wait_end(result, session, protocol):
    print('media is flowing via a different path than the relay for 4 minutes')
    defer = Deferred()
    defer.addCallback(end, session, protocol)
    reactor.callLater(240, defer.callback, None)
    return defer


def end(result, session, protocol):
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
    caller_media = caller.set_media([('audio', 40000, 'sendrecv', {'ice': 'yes'})])
    callee = Endpoint('Bob <bob@example.com>', 'Callee UA', False)
    callee_media = callee.set_media([('audio', 30000, 'sendrecv', {'ice': 'yes'})])
    session = Session(caller, callee)
    connector, defer = connect_to_dispatcher()
    defer.addCallback(caller_update, session, caller_media, callee_media)
    defer.addCallback(disconnect, connector)
    defer.addErrback(catch_all_err)
    reactor.run()
