oledump-contrib
===============

The oledump-contrib repository contains plugins and enhancements for the 
[oledump](http://blog.didierstevens.com/programs/oledump-py/) 
tool published by Didier Stevens.

Using this repo, you can submit new contributions: you may fork the project, then
submit your changes using pull requests. 

You may also send suggestions or bug reports using the issue tracker.

## Download

Get the latest version [here](https://bitbucket.org/decalage/oledump-contrib/get/tip.zip).

## New plugins 

### olevba plugin

oledump plugin to run the [olevba](https://bitbucket.org/decalage/oletools/wiki/olevba) scanning engine.

Main features:
- Detect auto-executable macros
- Detect suspicious VBA keywords often used by malware
- Detect and decodes strings obfuscated with Hex/Base64/StrReverse/Dridex
- Extract IOCs/patterns of interest such as IP addresses, URLs, e-mail addresses and executable file names

This plugin requires oletools, see https://bitbucket.org/decalage/oletools/wiki/Install

Usage: oledump.py -p plugin_olevba <file>

Example:

    :::text
    >oledump.py -p plugin_olevba \MalwareZoo\VBA\DEC1256DS.doc.zip
      1:       113 '\x01CompObj'
      2:      4096 '\x05DocumentSummaryInformation'
      3:      4096 '\x05SummaryInformation'
      4:      4096 '1Table'
      5:       436 'Macros/PROJECT'
      6:        41 'Macros/PROJECTwm'
      7: M   39148 'Macros/VBA/ThisDocument'
                   Plugin: olevba plugin
                     AutoExec: AutoOpen - Runs when the Word document is opened
                     AutoExec: Workbook_Open - Runs when the Excel Workbook is opened
                     Suspicious: Lib - May run code from a DLL
                     Suspicious: Shell - May run an executable file or a system command
                     Suspicious: Environ - May read system environment variables
                     Suspicious: Chr - May attempt to obfuscate specific strings
                     Suspicious: StrReverse - May attempt to obfuscate specific strings
                     Suspicious: URLDownloadToFileA - May download files from the Internet
                     Suspicious: Hex Strings - Hex-encoded strings were detected, may be used to obfuscate strings (option --decode to see all)
                     IOC: vGJsdfbJHKdsf.exe - Executable file name (obfuscation: Hex)
                     IOC: http://74.207.230.140:8080/mopsi/popsi.php - URL (obfuscation: StrReverse+Hex)
                     IOC: 74.207.230.140 - IPv4 address (obfuscation: StrReverse+Hex)
      8:      5004 'Macros/VBA/_VBA_PROJECT'
      9:       514 'Macros/VBA/dir'
     10:      4142 'WordDocument'
