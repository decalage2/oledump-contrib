#!/usr/bin/env python

# oledump plugin to run the olevba scanning engine
#
# Main features:
# - Detect auto-executable macros
# - Detect suspicious VBA keywords often used by malware
# - Detect and decodes strings obfuscated with Hex/Base64/StrReverse/Dridex
# - Extract IOCs/patterns of interest such as IP addresses, URLs, e-mail addresses and executable file names
#
# This plugin requires oletools, see https://bitbucket.org/decalage/oletools/wiki/Install
#
# olevba is part of the python-oletools package:
# http://www.decalage.info/python/oletools
#
# Author: Philippe Lagadec - http://www.decalage.info


__description__ = 'olevba plugin for oledump.py'
__author__ = 'Philippe Lagadec'
__version__ = '0.0.1'
__date__ = '2015-02-15'


try:
    import oletools.olevba
except ImportError:
    sys.exit('This plugin requires the oletools package, see https://bitbucket.org/decalage/oletools/wiki/Install')

class Plugin_olevba(cPluginParent):
    macroOnly = True
    name = 'olevba plugin'

    def __init__(self, name, stream, options):
        self.streamname = name
        self.stream = stream
        self.options = options
        self.ran = False

    def Analyze(self):
        self.ran = True
        vba_scanner = oletools.olevba.VBA_Scanner(oletools.olevba.filter_vba(self.stream))

        return ['%s: %s - %s' % (_type, string, desc) for _type, string, desc in vba_scanner.scan()]

AddPlugin(Plugin_olevba)
