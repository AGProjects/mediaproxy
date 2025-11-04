
"""Implementation of database accounting"""

import json

from application import log
from application.python.queue import EventQueue

from sqlobject import SQLObject, connectionForURI, sqlhub
from sqlobject import StringCol, BLOBCol, DatabaseIndex
from sqlobject.dberrors import DatabaseError, ProgrammingError, OperationalError

from mediaproxy.configuration import DatabaseConfig


if not DatabaseConfig.dburi:
    raise RuntimeError('Database accounting is enabled, but the database URI is not specified in config.ini')

connection = connectionForURI(DatabaseConfig.dburi)
sqlhub.processConnection = connection


class MediaSessions(SQLObject):
    class sqlmeta:
        table = DatabaseConfig.sessions_table
        createSQL = {'mysql': 'ALTER TABLE %s ENGINE MyISAM' % DatabaseConfig.sessions_table}
        cacheValues = False
    call_id = StringCol(length=255, dbName=DatabaseConfig.callid_column, notNone=True)
    from_tag = StringCol(length=64, dbName=DatabaseConfig.fromtag_column, notNone=True)
    to_tag = StringCol(length=64, dbName=DatabaseConfig.totag_column)
    info = BLOBCol(length=2**24-1, dbName=DatabaseConfig.info_column)  # 2**24-1 makes it a mediumblob in mysql, that can hold 16 million bytes
    # Indexes
    callid_idx = DatabaseIndex('call_id', 'from_tag', 'to_tag', unique=True)


try:
    MediaSessions.createTable(ifNotExists=True)
except OperationalError as e:
    log.error("cannot create the `%s' table: %s" % (DatabaseConfig.sessions_table, e))
    log.info("please make sure that the `%s' user has the CREATE and ALTER rights on the `%s' database" % (connection.user, connection.db))
    log.info('then restart the dispatcher, or you can create the table yourself using the following definition:')
    log.info('----------------- >8 -----------------')
    sql, constraints = MediaSessions.createTableSQL()
    statements = ';\n'.join([sql] + constraints) + ';'
    log.info(statements)
    log.info('----------------- >8 -----------------')
    # raise RuntimeError(str(e))


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
        names  = ', '.join([DatabaseConfig.callid_column, DatabaseConfig.fromtag_column, DatabaseConfig.totag_column, DatabaseConfig.info_column])
        values = ', '.join((sqlrepr(v) for v in [stats['call_id'], stats['from_tag'], stats['to_tag'], json.dumps(stats)]))
        q = 'INSERT INTO %s (%s) VALUES (%s)' % (DatabaseConfig.sessions_table, names, values)
        try:
            try:
                connection.query(q)
            except ProgrammingError as e:
                try:
                    MediaSessions.createTable(ifNotExists=True)
                except OperationalError:
                    raise e
                else:
                    connection.query(q)
        except DatabaseError as e:
            log.error('failed to insert record into database: %s' % e)

