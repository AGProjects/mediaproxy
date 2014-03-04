# Copyright (C) 2007-2014 Dan Pascu <dan@ag-projects.com>
#

"""Schedule calls on the twisted reactor"""


__all__ = ['RecurrentCall', 'KeepRunning']


from time import time


class KeepRunning:
    """Return this class from a recurrent function to indicate that it should keep running"""
    pass

class RecurrentCall(object):
    """Execute a function repeatedly at the given interval, until signaled to stop"""
    def __init__(self, period, func, *args, **kwargs):
        from twisted.internet import reactor
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.period = period
        self.now = None
        self.next = None
        self.callid = reactor.callLater(period, self)
    def __call__(self):
        from twisted.internet import reactor
        self.callid = None
        if self.now is None:
            self.now = time()
            self.next = self.now + self.period
        else:
            self.now, self.next = self.next, self.next + self.period
        result = self.func(*self.args, **self.kwargs)
        if result is KeepRunning:
            delay = max(self.next-time(), 0)
            self.callid = reactor.callLater(delay, self)
    def cancel(self):
        if self.callid is not None:
            try:
                self.callid.cancel()
            except ValueError:
                pass
            self.callid = None


