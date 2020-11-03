
"""Implementation of RADIUS accounting"""

from application import log
from application.process import process
from application.python.queue import EventQueue

import pyrad.client
import pyrad.dictionary

from mediaproxy.configuration import RadiusConfig


try:
    from pyrad.dictfile import DictFile
except ImportError:
    # helper class to make pyrad support the $INCLUDE statement in dictionary files
    class RadiusDictionaryFile(object):
        def __init__(self, base_file_name):
            self.file_names = [base_file_name]
            self.fd_stack = [open(base_file_name)]

        def readlines(self):
            while True:
                line = self.fd_stack[-1].readline()
                if line:
                    if line.startswith('$INCLUDE'):
                        file_name = line.rstrip('\n').split(None, 1)[1]
                        if file_name not in self.file_names:
                            self.file_names.append(file_name)
                            self.fd_stack.append(open(file_name))
                        continue
                    else:
                        yield line
                else:
                    self.fd_stack.pop()
                    if len(self.fd_stack) == 0:
                        return
else:
    del DictFile
    class RadiusDictionaryFile(str):
        pass


class Accounting(object):

    def __init__(self):
        self.handler = RadiusAccounting()

    def start(self):
        self.handler.start()

    def do_accounting(self, stats):
        self.handler.put(stats)

    def stop(self):
        self.handler.stop()
        self.handler.join()


class RadiusAccounting(EventQueue, pyrad.client.Client):

    def __init__(self):
        main_config_file = process.configuration.file(RadiusConfig.config_file)
        if main_config_file is None:
            raise RuntimeError('Cannot find the radius configuration file: %r' % RadiusConfig.config_file)
        try:
            config = dict(line.rstrip('\n').split(None, 1) for line in open(main_config_file) if len(line.split(None, 1)) == 2 and not line.startswith('#'))
            secrets = dict(line.rstrip('\n').split(None, 1) for line in open(config['servers']) if len(line.split(None, 1)) == 2 and not line.startswith('#'))
            server = config['acctserver']
            try:
                server, acctport = server.split(':')
                acctport = int(acctport)
            except ValueError:
                log.info('Could not load additional RADIUS dictionary file: %r' % RadiusConfig.additional_dictionary)
                acctport = 1813
            log.info('Using RADIUS server at %s:%d' % (server, acctport))
            secret = secrets[server]
            log.info("Using RADIUS dictionary file %s" % config['dictionary'])
            dicts = [RadiusDictionaryFile(config['dictionary'])]
            if RadiusConfig.additional_dictionary:
                additional_dictionary = process.configuration.file(RadiusConfig.additional_dictionary)
                if additional_dictionary:
                    log.info("Using additional RADIUS dictionary file %s" % RadiusConfig.additional_dictionary)
                    dicts.append(RadiusDictionaryFile(additional_dictionary))
                else:
                    log.warning('Could not load additional RADIUS dictionary file: %r' % RadiusConfig.additional_dictionary)
            raddict = pyrad.dictionary.Dictionary(*dicts)
            timeout = int(config['radius_timeout'])
            retries = int(config['radius_retries'])
        except Exception:
            log.critical('cannot read the RADIUS configuration file %s' % RadiusConfig.config_file)
            raise
        pyrad.client.Client.__init__(self, server, 1812, acctport, 3799, secret, raddict)
        self.timeout = timeout
        self.retries = retries
        if 'bindaddr' in config and config['bindaddr'] != '*':
            self.bind((config['bindaddr'], 0))
        EventQueue.__init__(self, self.do_accounting)

    def do_accounting(self, stats):
        attrs = {}
        attrs['Acct-Status-Type'] = 'Update'
        attrs['User-Name'] = 'mediaproxy@default'
        attrs['Acct-Session-Id'] = stats['call_id']
        attrs['Acct-Session-Time'] = stats['duration']
        attrs['Acct-Input-Octets'] = sum(stream_stats['caller_bytes'] for stream_stats in stats['streams'])
        attrs['Acct-Output-Octets'] = sum(stream_stats['callee_bytes'] for stream_stats in stats['streams'])
        attrs['Sip-From-Tag'] = stats['from_tag']
        attrs['Sip-To-Tag'] = stats['to_tag'] or ''
        attrs['NAS-IP-Address'] = stats['streams'][0]['caller_local'].split(':')[0]
        attrs['Sip-User-Agents'] = (stats['caller_ua'] + '+' + stats['callee_ua'])[:253]
        attrs['Sip-Applications'] = ', '.join(sorted(set(stream['media_type'] for stream in stats['streams'] if stream['start_time'] != stream['end_time'])))[:253]
        attrs['Media-Codecs'] = ', '.join(stream['caller_codec'] for stream in stats['streams'])[:253]
        if stats['timed_out'] and not stats.get('all_streams_ice', False):
            attrs['Media-Info'] = 'timeout'
        elif stats.get('all_streams_ice', False):
            attrs['Media-Info'] = 'ICE session'
        else:
            attrs['Media-Info'] = ''
        for stream in stats['streams']:
            if stream['post_dial_delay'] is not None:
                attrs['Acct-Delay-Time'] = int(stream['post_dial_delay'])
                break
        if isinstance(self.secret, str):
            scr_bn = self.secret.encode('utf-8')
            self.secret = scr_bn
        try:
            self.SendPacket(self.CreateAcctPacket(**attrs))
        except Exception as e:
            log.error('Failed to send radius accounting record: %s' % e)
