#!/usr/bin/python

from distutils.core import setup, Extension
import sys
import re

import mediaproxy

# Get the title and description from README
readme = open('README').read()
title, description = re.findall(r'^\s*([^\n]+)\s+(.*)$', readme, re.DOTALL)[0]

setup(name         = "mediaproxy",
      version      = mediaproxy.__version__,
      author       = "Ruud Klaver",
      author_email = "ruud@ag-projects.com",
      url          = "http://www.ag-projects.com/MediaProxy.html",
      description  = title,
      long_description = description,
      license      = "GPL",
      platforms    = ["Linux"],
      classifiers  = [
          #"Development Status :: 1 - Planning",
          "Development Status :: 2 - Pre-Alpha",
          #"Development Status :: 3 - Alpha",
          #"Development Status :: 4 - Beta",
          #"Development Status :: 5 - Production/Stable",
          #"Development Status :: 6 - Mature",
          #"Development Status :: 7 - Inactive",
          "Intended Audience :: Service Providers",
          "License :: GNU General Public License (GPL)",
          "Operating System :: POSIX :: Linux",
          "Programming Language :: Python",
          "Programming Language :: C"
      ],
      packages     = ['mediaproxy', 'mediaproxy.interfaces', 'mediaproxy.interfaces.system'],
      scripts      = ['mp-relay', 'mp-dispatcher'],
      ext_modules  = [
          Extension(name = 'mediaproxy.interfaces.system._conntrack',
                    sources = ['mediaproxy/interfaces/system/_conntrack.c'],
                    libraries = ["iptc", "netfilter_conntrack"],
                    define_macros = [('MODULE_VERSION', mediaproxy.__version__)])
      ]
)

