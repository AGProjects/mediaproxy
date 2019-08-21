#!/usr/bin/python

import re
import sys
import mediaproxy

from distutils.core import setup, Extension

# Get the title and description from README
readme = open('README').read()
title, description = re.findall(r'^\s*([^\n]+)\s+(.*)$', readme, re.DOTALL)[0]

# media-relay is not supported on non-linux platforms
#
if sys.platform == 'linux2':
    scripts = ['media-relay', 'media-dispatcher']
    ext_modules = [Extension(name='mediaproxy.interfaces.system._conntrack',
                             sources=['mediaproxy/interfaces/system/_conntrack.c'],
                             libraries=['netfilter_conntrack', 'ip4tc'],
                             define_macros=[('MODULE_VERSION', mediaproxy.__version__)])]
else:
    print('WARNING: skipping the media relay component as this is a non-linux platform')
    scripts = ['media-dispatcher']
    ext_modules = []


setup(
    name='mediaproxy',
    version=mediaproxy.__version__,

    description=title,
    long_description=description,
    url='http://www.ag-projects.com/MediaProxy.html',

    author='AG Projects',
    author_email='support@ag-projects.com',

    license='GPLv2',
    platforms=['Linux'],

    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Service Providers',
        'License :: GNU General Public License (GPLv2)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: C'
    ],

    packages=['mediaproxy', 'mediaproxy.configuration', 'mediaproxy.interfaces', 'mediaproxy.interfaces.accounting', 'mediaproxy.interfaces.system'],
    scripts=scripts,
    ext_modules=ext_modules
)
