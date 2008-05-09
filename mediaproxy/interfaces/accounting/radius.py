#
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
    config_file = "/etc/openser/radius/client.conf"
    additional_dictionary = process.config_file("radius/dictionary")


configuration = ConfigFile(configuration_filename)
configuration.read_settings("Radius", Config)

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
        try:
            config = dict(line.rstrip("\n").split(None, 1) for line in open(Config.config_file) if len(line.split(None, 1)) == 2 and not line.startswith("#"))
            secrets = dict(line.rstrip("\n").split(None, 1) for line in open(config["servers"]) if len(line.split(None, 1)) == 2 and not line.startswith("#"))
            server = config["acctserver"]
            if ":" in server:
                server, acctport = server.split(":")
            else:
                acctport = 1813
            secret = secrets[server]
            # pyrad does not support $INCLUDE in dictionary files!
            dicts = [line.rstrip("\n").split(None, 1)[1] for line in open(config["dictionary"]) if line.startswith("$INCLUDE")] + [config["dictionary"]]
            if Config.additional_dictionary is not None:
                dicts.append(Config.additional_dictionary)
            raddict = pyrad.dictionary.Dictionary(*dicts)
            timeout = int(config["radius_timeout"])
            retries = int(config["radius_retries"])
        except Exception, e:
            log.fatal("Error reading RADIUS configuration file")
            raise
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
        attrs["Acct-Input-Octets"] = sum(bytes for bytes in stats["caller_bytes"].itervalues())
        attrs["Acct-Output-Octets"] = sum(bytes for bytes in stats["callee_bytes"].itervalues())
        attrs["Sip-From-Tag"] = stats["from_tag"]
        attrs["Sip-To-Tag"] = stats["to_tag"]
        attrs["Sip-User-Agents"] = (stats["caller_ua"] + "+" + stats["callee_ua"])[:253]
        attrs["Sip-Applications"] = stats["streams"][0]["media_type"]
        attrs["Media-Codecs"] = stats["streams"][0]["caller_codec"]
        if stats["streams"][-1]["status"] != "closed":
            attrs["Media-Info"] = "timeout"
        else:
            attrs["Media-Info"] = ""
        self.SendPacket(self.CreateAcctPacket(**attrs))
