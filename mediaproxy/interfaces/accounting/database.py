# Copyright (C) 2008 AG Projects
# Author: Ruud Klaver <ruud@ag-projects.com>
#

"""Implementation of database accounting"""

import cjson

from application import log
from application.python.queue import EventQueue
from application.configuration import ConfigSection

from sqlobject import SQLObject, connectionForURI, sqlhub
from sqlobject import StringCol, BLOBCol, DatabaseIndex
from sqlobject.dberrors import DatabaseError, ProgrammingError, OperationalError

from mediaproxy import configuration_filename


class Config(ConfigSection):
    __cfgfile__ = configuration_filename
    __section__ = 'Database'

    dburi = ""
    sessions_table = "media_sessions"
    callid_column = "call_id"
    fromtag_column = "from_tag"
    totag_column = "to_tag"
    info_column = "info"


if not Config.dburi:
    raise RuntimeError("Database accounting is enabled, but the database URI is not specified in config.ini")

connection = connectionForURI(Config.dburi)
sqlhub.processConnection = connection


class MediaSessions(SQLObject):
    class sqlmeta:
        table = Config.sessions_table
        createSQL = {'mysql': 'ALTER TABLE %s ENGINE MyISAM' % Config.sessions_table}
        cacheValues = False
    call_id = StringCol(length=255, dbName=Config.callid_column, notNone=True)
    from_tag = StringCol(length=64, dbName=Config.fromtag_column, notNone=True)
    to_tag = StringCol(length=64, dbName=Config.totag_column)
    info = BLOBCol(length=2**24-1, dbName=Config.info_column) # 2**24-1 makes it a mediumblob in mysql, that can hold 16 million bytes
    ## Indexes
    callid_idx = DatabaseIndex('call_id', 'from_tag', 'to_tag', unique=True)


try:
    MediaSessions.createTable(ifNotExists=True)
except OperationalError, e:
    log.error("cannot create the `%s' table: %s" % (Config.sessions_table, e))
    log.msg("please make sure that the `%s' user has the CREATE and ALTER rights on the `%s' database" % (connection.user, connection.db))
    log.msg("then restart the dispatcher, or you can create the table yourself using the following definition:")
    log.msg("----------------- >8 -----------------")
    sql, constraints = MediaSessions.createTableSQL()
    statements = ';\n'.join([sql] + constraints) + ';'
    log.msg(statements)
    log.msg("----------------- >8 -----------------")
    #raise RuntimeError(str(e))


class Accounting(object):

    def __init__(self):
        self.handler = DatabaseAccounting()

    def start(self):
        self.handler.start()

    def do_accounting(self, stats):
        self.handler.put(stats)

    def stop(self):
        self.handler.stop()
        self.handler.join()


class DatabaseAccounting(EventQueue):

    def __init__(self):
        EventQueue.__init__(self, self.do_accounting)

    def do_accounting(self, stats):
        sqlrepr = connection.sqlrepr
        names  = ', '.join([Config.callid_column, Config.fromtag_column, Config.totag_column, Config.info_column])
        values = ', '.join((sqlrepr(v) for v in [stats["call_id"], stats["from_tag"], stats["to_tag"], cjson.encode(stats)]))
        q = """INSERT INTO %s (%s) VALUES (%s)""" % (Config.sessions_table, names, values)
        try:
            try:
                connection.query(q)
            except ProgrammingError, e:
                try:
                    MediaSessions.createTable(ifNotExists=True)
                except OperationalError:
                    raise e
                else:
                    connection.query(q)
        except DatabaseError, e:
            log.error("failed to insert record into database: %s" % e)

