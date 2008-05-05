#
# Copyright (C) 2008 AG Projects
# Author: Ruud Klaver <ruud@ag-projects.com>
#

"""Implementation of database accounting"""

from collections import deque
import cjson

from application import log
from application.process import process
from application.python.queue import EventQueue
from application.configuration import *

from sqlobject import SQLObject, connectionForURI, sqlhub
from sqlobject import StringCol, BLOBCol

from mediaproxy import configuration_filename

class Sessions(SQLObject):
    call_id = StringCol(notNone=True)
    from_tag = StringCol(notNone=True)
    to_tag = StringCol(notNone=True)
    statistics = BLOBCol()

class Config(ConfigSection):
    dburi = "mysql://user:password@host/database"
    pool_size = 1

configuration = ConfigFile(configuration_filename)
configuration.read_settings("Database", Config)

sqlhub.processConnection = connectionForURI(Config.dburi)

class Accounting(object):

    def __init__(self):
        self.databases = deque(DatabaseAccounting() for i in range(Config.pool_size))

    def start(self):
        for db in self.databases:
            db.start()

    def do_accounting(self, stats):
        db = self.databases.popleft()
        db.put(stats)
        self.databases.append(db)

    def stop(self):
        for db in self.databases:
            db.stop()
        for db in self.databases:
            db.join()


class DatabaseAccounting(EventQueue):

    def __init__(self):
        EventQueue.__init__(self, self.do_accounting)

    def do_accounting(self, stats):
        Sessions(call_id=stats["call_id"], from_tag=stats["from_tag"], to_tag=stats["to_tag"], statistics=cjson.encode(stats))
