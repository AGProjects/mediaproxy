# Copyright (C) 2008 AG Projects
# Author: Ruud Klaver <ruud@ag-projects.com>
#

"""Implementation of RADIUS accounting"""

from application import log
from application.process import process
from application.python.queue import EventQueue
from application.configuration import *

import pyrad.client
import pyrad.dictionary

from mediaproxy import configuration_filename

class Config(ConfigSection):
    config_file = "/etc/opensips/radius/client.conf"
    additional_dictionary = "radius/dictionary"


configuration = ConfigFile(configuration_filename)
configuration.read_settings("Radius", Config)

# helper class to make pyrad support the $INCLUDE statement in dictionary files
class RadiusDictionaryFile(object):

    def __init__(self, base_file_name):
        self.file_names = [base_file_name]
        self.fd_stack = [open(base_file_name)]

    def readlines(self):
        while True:
            line = self.fd_stack[-1].readline()
            if line:
                if line.startswith("$INCLUDE"):
                    file_name = line.rstrip("\n").split(None, 1)[1]
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


class Accounting(object):

    def __init__(self):
        self.radius = RadiusAccounting()

    def start(self):
        self.radius.start()

    def do_accounting(self, stats):
        self.radius.put(stats)

    def stop(self):
        self.radius.stop()
        self.radius.join()


class RadiusAccounting(EventQueue, pyrad.client.Client):

    def __init__(self):
        main_config_file = process.config_file(Config.config_file)
        if main_config_file is None:
            raise RuntimeError("Cannot find the radius configuration file: `%s'" % Config.config_file)
        try:
            config = dict(line.rstrip("\n").split(None, 1) for line in open(main_config_file) if len(line.split(None, 1)) == 2 and not line.startswith("#"))
            secrets = dict(line.rstrip("\n").split(None, 1) for line in open(config["servers"]) if len(line.split(None, 1)) == 2 and not line.startswith("#"))
            server = config["acctserver"]
            if ":" in server:
                server, acctport = server.split(":")
            else:
                acctport = 1813
            secret = secrets[server]
            dicts = [RadiusDictionaryFile(config["dictionary"])]
            if Config.additional_dictionary:
                additional_dictionary = process.config_file(Config.additional_dictionary)
                if additional_dictionary:
                    dicts.append(RadiusDictionaryFile(additional_dictionary))
                else:
                    log.warn("Could not load additional RADIUS dictionary file: `%s'" % Config.additional_dictionary)
            raddict = pyrad.dictionary.Dictionary(*dicts)
            timeout = int(config["radius_timeout"])
            retries = int(config["radius_retries"])
        except Exception, e:
            log.fatal("cannot read the RADIUS configuration file")
            raise RuntimeError(str(e))
        pyrad.client.Client.__init__(self, server, 1812, acctport, secret, raddict)
        self.timeout = timeout
        self.retries = retries
        EventQueue.__init__(self, self.do_accounting)

    def do_accounting(self, stats):
        attrs = {}
        attrs["Acct-Status-Type"] = "Update"
        attrs["User-Name"] = "mediaproxy@default"
        attrs["Acct-Session-Id"] = stats["call_id"]
        attrs["Acct-Session-Time"] = stats["duration"]
        attrs["Acct-Input-Octets"] = sum(stats["caller_bytes"].itervalues())
        attrs["Acct-Output-Octets"] = sum(stats["callee_bytes"].itervalues())
        attrs["Sip-From-Tag"] = stats["from_tag"]
        attrs["Sip-To-Tag"] = stats["to_tag"]
        attrs["NAS-IP-Address"] = stats["streams"][0]["caller_local"].split(":")[0]
        attrs["Sip-User-Agents"] = (stats["caller_ua"] + "+" + stats["callee_ua"])[:253]
        attrs["Sip-Applications"] = ', '.join(sorted(set(stream['media_type'] for stream in stats['streams'])))[:253]
        attrs["Media-Codecs"] = ', '.join(stream['caller_codec'] for stream in stats['streams'])[:253]
        if stats["timed_out"]:
            attrs["Media-Info"] = "timeout"
        else:
            attrs["Media-Info"] = ""
        for stream in stats["streams"]:
            if stream["pdd"] is not None:
                attrs["Delay-Time"] = int(stream["pdd"])
                break
        self.SendPacket(self.CreateAcctPacket(**attrs))
