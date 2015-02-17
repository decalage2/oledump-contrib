#!/usr/bin/env python

__description__ = 'Process command'
__author__ = 'Didier Stevens'
__version__ = '0.0.8'
__date__ = '2015/02/10'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

# http://www.wordarticles.com/Articles/Formats/StreamCompression.php

History:
  2014/08/21: start
  2014/08/22: added ZIP support
  2014/08/23: added stdin support
  2014/08/25: added options extract and info
  2014/08/26: bugfix pipe
  2014/09/01: added * as selection option
  2014/09/15: exception handling for import OleFileIO_PL
  2014/11/12: added plugins
  2014/11/15: continued plugins
  2014/11/21: added pluginoptions
  2014/12/14: 0.0.3: Added YARA support; added decoders
  2014/12/19: 0.0.4: fixed bug when file was not OLE
  2014/12/24: 0.0.5: fixed storage bug and added MacrosContainsOnlyAttributes
  2014/12/25: 0.0.6: added support for ZIP containers with OLE files, like .docx
  2014/12/26: added printing of filename OLE files inside ZIP
  2014/12/31: suppressed printing of filename when selecting
  2015/02/09: 0.0.7: added handling of .docx, ... inside ZIP file; Added option yarastrings
  2015/02/10: 0.0.8: added YARACompile

Todo:
"""

import optparse
import sys
import math
import os
import zipfile
import cStringIO
import binascii
try:
    import yara
except:
    pass

try:
    import OleFileIO_PL
except:
    print('This program requires module OleFileIO_PL.\nhttp://www.decalage.info/python/olefileio\n')
    exit(-1)

dumplinelength = 16
MALWARE_PASSWORD = 'infected'
OLEFILE_MAGIC = '\xD0\xCF\x11\xE0'

#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string

# CIC: Call If Callable
def CIC(expression):
    if callable(expression):
        return expression()
    else:
        return expression

# IFF: IF Function
def IFF(expression, valueTrue, valueFalse):
    if expression:
        return CIC(valueTrue)
    else:
        return CIC(valueFalse)

def File2String(filename):
    try:
        f = open(filename, 'rb')
    except:
        return None
    try:
        return f.read()
    except:
        return None
    finally:
        f.close()

class cDumpStream():
    def __init__(self):
        self.text = ''

    def Addline(self, line):
        if line != '':
            self.text += line + '\n'

    def Content(self):
        return self.text

def HexDump(data):
    oDumpStream = cDumpStream()
    hexDump = ''
    for i, b in enumerate(data):
        if i % dumplinelength == 0 and hexDump != '':
            oDumpStream.Addline(hexDump)
            hexDump = ''
        hexDump += IFF(hexDump == '', '', ' ') + '%02X' % ord(b)
    oDumpStream.Addline(hexDump)
    return oDumpStream.Content()

def CombineHexAscii(hexDump, asciiDump):
    if hexDump == '':
        return ''
    return hexDump + '  ' + (' ' * (3 * (dumplinelength - len(asciiDump)))) + asciiDump

def HexAsciiDump(data):
    oDumpStream = cDumpStream()
    hexDump = ''
    asciiDump = ''
    for i, b in enumerate(data):
        if i % dumplinelength == 0:
            if hexDump != '':
                oDumpStream.Addline(CombineHexAscii(hexDump, asciiDump))
            hexDump = '%08X:' % i
            asciiDump = ''
        hexDump+= ' %02X' % ord(b)
        asciiDump += IFF(ord(b) >= 32 and ord(b), b, '.')
    oDumpStream.Addline(CombineHexAscii(hexDump, asciiDump))
    return oDumpStream.Content()

#Fix for http://bugs.python.org/issue11395
def StdoutWriteChunked(data):
    while data != '':
        sys.stdout.write(data[0:10000])
        try:
            sys.stdout.flush()
        except IOError:
            return
        data = data[10000:]

def PrintableName(fname):
    return repr('/'.join(fname))

def ParseTokenSequence(data):
    flags = ord(data[0])
    data = data[1:]
    result = []
    for mask in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]:
        if len(data) > 0:
            if flags & mask:
                result.append(data[0:2])
                data = data[2:]
            else:
                result.append(data[0])
                data = data[1:]
    return result, data

def OffsetBits(data):
    numberOfBits = int(math.ceil(math.log(len(data), 2)))
    if numberOfBits < 4:
        numberOfBits = 4
    elif numberOfBits > 12:
        numberOfBits = 12
    return numberOfBits

def Bin(number):
    result = bin(number)[2:]
    while len(result) < 16:
        result = '0' + result
    return result

def DecompressChunk(compressedChunk):
    header = ord(compressedChunk[0]) + ord(compressedChunk[1]) * 0x100
    size = (header & 0x0FFF) + 3
    flagCompressed = header & 0x8000
    data = compressedChunk[2:2 + size - 2]

    if flagCompressed == 0:
        return data, compressedChunk[size:]

    decompressedChunk = ''
    while len(data) != 0:
        tokens, data = ParseTokenSequence(data)
        for token in tokens:
            if len(token) == 1:
                decompressedChunk += token
            else:
                numberOfOffsetBits = OffsetBits(decompressedChunk)
                copyToken = ord(token[0]) + ord(token[1]) * 0x100
                offset = 1 + (copyToken >> (16 - numberOfOffsetBits))
                length = 3 + (((copyToken << numberOfOffsetBits) & 0xFFFF) >> numberOfOffsetBits)
                copy = decompressedChunk[-offset:]
                copy = copy[0:length]
                lengthCopy = len(copy)
                while length > lengthCopy: #a#
                    if length - lengthCopy >= lengthCopy:
                        copy += copy[0:lengthCopy]
                        length -= lengthCopy
                    else:
                        copy += copy[0:length - lengthCopy]
                        length -= length - lengthCopy
                decompressedChunk += copy
    return decompressedChunk, compressedChunk[size:]

def Decompress(compressedData):
    if compressedData[0] != chr(1):
        return None
    remainder = compressedData[1:]
    decompressed = ''
    while len(remainder) != 0:
        decompressedChunk, remainder = DecompressChunk(remainder)
        decompressed += decompressedChunk
    return decompressed

def SearchAndDecompress(data):
    position = data.find('\x00Attribut')
    if position == -1:
        compressedData = data
    else:
        compressedData = data[position - 3:]
    result = Decompress(compressedData)
    if result == None:
        return 'Error: unable to decompress'
    else:
        return result

def ReadWORD(data):
    if len(data) < 2:
        return None, None
    return ord(data[0]) + ord(data[1]) *0x100, data[2:]

def ReadDWORD(data):
    if len(data) < 4:
        return None, None
    return ord(data[0]) + ord(data[1]) *0x100 + ord(data[2]) *0x10000 + ord(data[3]) *0x1000000, data[4:]

def ReadNullTerminatedString(data):
    position = data.find('\x00')
    if position == -1:
        return None, None
    return data[:position], data[position + 1:]

def ExtractOle10Native(data):
    size, data = ReadDWORD(data)
    if size == None:
        return []
    dummy, data = ReadWORD(data)
    if dummy == None:
        return []
    filename, data = ReadNullTerminatedString(data)
    if filename == None:
        return []
    pathname, data = ReadNullTerminatedString(data)
    if pathname == None:
        return []
    dummy, data = ReadDWORD(data)
    if dummy == None:
        return []
    dummy, data = ReadDWORD(data)
    if dummy == None:
        return []
    temppathname, data = ReadNullTerminatedString(data)
    if temppathname == None:
        return []
    sizeEmbedded, data = ReadDWORD(data)
    if sizeEmbedded == None:
        return []
    if len(data) < sizeEmbedded:
        return []

    return [filename, pathname, temppathname, data[:sizeEmbedded]]

def Extract(data):
    result = ExtractOle10Native(data)
    if result == []:
        return 'Error: extraction failed'
    return result[3]

def Info(data):
    result = ExtractOle10Native(data)
    if result == []:
        return 'Error: extraction failed'
    return 'String 1: %s\nString 2: %s\nString 3: %s\nSize embedded file: %d\n' % (result[0], result[1], result[2], len(result[3]))

def IfWIN32SetBinary(io):
    if sys.platform == 'win32':
        import msvcrt
        msvcrt.setmode(io.fileno(), os.O_BINARY)

def File2Strings(filename):
    try:
        f = open(filename, 'r')
    except:
        return None
    try:
        return map(lambda line:line.rstrip('\n'), f.readlines())
    except:
        return None
    finally:
        f.close()

def ProcessAt(argument):
    if argument.startswith('@'):
        strings = File2Strings(argument[1:])
        if strings == None:
            raise Exception('Error reading %s' % argument)
        else:
            return strings
    else:
        return [argument]

def AddPlugin(cClass):
    global plugins

    plugins.append(cClass)

def ExpandFilenameArguments(filenames):
    return list(collections.OrderedDict.fromkeys(sum(map(glob.glob, sum(map(ProcessAt, filenames), [])), [])))

class cPluginParent():
    macroOnly = False

def LoadPlugins(plugins, verbose):
    if plugins == '':
        return
    scriptPath = os.path.dirname(sys.argv[0])
    for plugin in sum(map(ProcessAt, plugins.split(',')), []):
        try:
            if not plugin.lower().endswith('.py'):
                plugin += '.py'
            if os.path.dirname(plugin) == '':
                if not os.path.exists(plugin):
                    scriptPlugin = os.path.join(scriptPath, plugin)
                    if os.path.exists(scriptPlugin):
                        plugin = scriptPlugin
            exec open(plugin, 'r') in globals(), globals()
        except Exception as e:
            print('Error loading plugin: %s' % plugin)
            if verbose:
                raise e

def AddDecoder(cClass):
    global decoders

    decoders.append(cClass)

class cDecoderParent():
    pass

def LoadDecoders(decoders, verbose):
    if decoders == '':
        return
    scriptPath = os.path.dirname(sys.argv[0])
    for decoder in sum(map(ProcessAt, decoders.split(',')), []):
        try:
            if not decoder.lower().endswith('.py'):
                decoder += '.py'
            if os.path.dirname(decoder) == '':
                if not os.path.exists(decoder):
                    scriptDecoder = os.path.join(scriptPath, decoder)
                    if os.path.exists(scriptDecoder):
                        decoder = scriptDecoder
            exec open(decoder, 'r') in globals(), globals()
        except Exception as e:
            print('Error loading decoder: %s' % decoder)
            if verbose:
                raise e

class cIdentity(cDecoderParent):
    name = 'Identity function decoder'

    def __init__(self, stream, options):
        self.stream = stream
        self.options = options
        self.available = True

    def Available(self):
        return self.available

    def Decode(self):
        self.available = False
        return self.stream

    def Name(self):
        return ''

def DecodeFunction(decoders, options, stream):
    if decoders == []:
        return stream
    return decoders[0](stream, options.decoderoptions).Decode()

def MacrosContainsOnlyAttributes(stream):
    lines = SearchAndDecompress(stream).split('\n')
    for line in [line.strip() for line in lines]:
        if line != '' and not line.startswith('Attribute '):
            return False
    return True

def OLESub(ole, prefix, rules, options):
    global plugins
    global decoders

    if options.select == '':
        counter = 1
        for fname in ole.listdir():
            stream = None
            indicator = ' '
            macroPresent = False
            lenghString = '      '
            if ole.get_type(fname) == 1:
                indicator = '.'
            elif ole.get_type(fname) == 2:
                stream = ole.openstream(fname).read()
                lenghString = '%7d' % len(stream)
                macroPresent = '\x00Attribut' in stream
                if macroPresent:
                    indicator = 'M'
                    if MacrosContainsOnlyAttributes(stream):
                        indicator = 'm'
            print('%3s: %s %s %s' % (('%s%d' % (prefix, counter)), indicator, lenghString, PrintableName(fname)))
            for cPlugin in plugins:
                try:
                    if cPlugin.macroOnly and macroPresent:
                        oPlugin = cPlugin(fname, SearchAndDecompress(stream), options.pluginoptions)
                    elif not cPlugin.macroOnly:
                        oPlugin = cPlugin(fname, stream, options.pluginoptions)
                    else:
                        oPlugin = None
                except Exception as e:
                    print('Error instantiating plugin: %s' % cPlugin.name)
                    if options.verbose:
                        raise e
                    return
                if oPlugin != None:
                    result = oPlugin.Analyze()
                    if oPlugin.ran:
                        print('               Plugin: %s ' % oPlugin.name)
                        for line in result:
                            print('                 ' + line)
            counter += 1
            if options.yara != None:
                oDecoders = [cIdentity(stream, None)]
                for cDecoder in decoders:
                    try:
                        oDecoder = cDecoder(stream, options.decoderoptions)
                        oDecoders.append(oDecoder)
                    except Exception as e:
                        print('Error instantiating decoder: %s' % cDecoder.name)
                        if options.verbose:
                            raise e
                        return
                for oDecoder in oDecoders:
                    while oDecoder.Available():
                        for result in rules.match(data=oDecoder.Decode()):
                            print('               YARA rule%s: %s' % (IFF(oDecoder.Name() == '', '', ' (stream decoder: %s)' % oDecoder.Name()), result.rule))
                            if options.yarastrings:
                                for stringdata in result.strings:
                                    print('               %06x %s:' % (stringdata[0], stringdata[1]))
                                    print('                %s' % binascii.hexlify(C2BIP3(stringdata[2])))
                                    print('                %s' % repr(stringdata[2]))
    else:
        if len(decoders) > 1:
            print('Error: provide only one decoder when using option select')
            return
        if options.dump:
            DumpFunction = lambda x:x
            IfWIN32SetBinary(sys.stdout)
        elif options.hexdump:
            DumpFunction = HexDump
        elif options.vbadecompress:
            DumpFunction = SearchAndDecompress
        elif options.extract:
            DumpFunction = Extract
            IfWIN32SetBinary(sys.stdout)
        elif options.info:
            DumpFunction = Info
        else:
            DumpFunction = HexAsciiDump
        counter = 1
        for fname in ole.listdir():
            if options.select == 'a' or ('%s%d' % (prefix, counter)) == options.select:
                StdoutWriteChunked(DumpFunction(DecodeFunction(decoders, options, ole.openstream(fname).read())))
                if options.select != 'a':
                    break
            counter += 1

def YARACompile(fileordirname):
    dFilepaths = {}
    if os.path.isdir(fileordirname):
        for root, dirs, files in os.walk(fileordirname):
            for file in files:
                filename = os.path.join(root, file)
                dFilepaths[filename] = filename
    else:
        for filename in ProcessAt(fileordirname):
            dFilepaths[filename] = filename
    return yara.compile(filepaths=dFilepaths)

def OLEDump(filename, options):
    global plugins
    plugins = []
    LoadPlugins(options.plugins, True)

    global decoders
    decoders = []
    LoadDecoders(options.decoders, True)

    if options.raw:
        print(SearchAndDecompress(File2String(filename)))
        return

    rules = None
    if options.yara != None:
        if not 'yara' in sys.modules:
            print('Error: option yara requires the YARA Python module.')
            return
        rules = YARACompile(options.yara)

    if filename == '':
        IfWIN32SetBinary(sys.stdin)
        oStringIO = cStringIO.StringIO(sys.stdin.read())
    elif filename.lower().endswith('.zip'):
        oZipfile = zipfile.ZipFile(filename, 'r')
        oZipContent = oZipfile.open(oZipfile.infolist()[0], 'r', C2BIP3(MALWARE_PASSWORD))
        oStringIO = cStringIO.StringIO(oZipContent.read())
        oZipContent.close()
        oZipfile.close()
    else:
        oStringIO = cStringIO.StringIO(open(filename, 'rb').read())

    magic = oStringIO.read(4)
    if magic[0:2] == 'PK':
        oZipfile = zipfile.ZipFile(oStringIO, 'r')
        counter = 0
        for info in oZipfile.infolist():
            oZipContent = oZipfile.open(info, 'r')
            content = oZipContent.read()
            if content[0:4] == OLEFILE_MAGIC:
                letter = chr(ord('A') + counter)
                counter += 1
                if options.select == '':
                    print('%s: %s' % (letter, info.filename))
                ole = OleFileIO_PL.OleFileIO(cStringIO.StringIO(content))
                OLESub(ole, letter, rules, options)
                ole.close()
            oZipContent.close()
        oZipfile.close()
    elif magic != OLEFILE_MAGIC:
        print('Error: %s is not a valid OLE file.' % filename)
    else:
        ole = OleFileIO_PL.OleFileIO(oStringIO)
        OLESub(ole, '', rules, options)
        ole.close()

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] [file]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-s', '--select', default='', help='select item nr for dumping (a for all)')
    oParser.add_option('-d', '--dump', action='store_true', default=False, help='perform dump')
    oParser.add_option('-x', '--hexdump', action='store_true', default=False, help='perform hex dump')
    oParser.add_option('-a', '--asciidump', action='store_true', default=False, help='perform ascii dump')
    oParser.add_option('-v', '--vbadecompress', action='store_true', default=False, help='VBA decompression')
    oParser.add_option('-r', '--raw', action='store_true', default=False, help='raw file, attempt VBA decompression')
    oParser.add_option('-e', '--extract', action='store_true', default=False, help='extract OLE embedded file')
    oParser.add_option('-i', '--info', action='store_true', default=False, help='print extra info for selected item')
    oParser.add_option('-p', '--plugins', type=str, default='', help='plugins to load (separate plugins with a comma , ; @file supported)')
    oParser.add_option('--pluginoptions', type=str, default='', help='options for the plugin')
    oParser.add_option('-y', '--yara', help="YARA rule to check streams (YARA search doesn't work with -s option)")
    oParser.add_option('-D', '--decoders', type=str, default='', help='decoders to load (separate decoders with a comma , ; @file supported)')
    oParser.add_option('--decoderoptions', type=str, default='', help='options for the decoder')
    oParser.add_option('--yarastrings', action='store_true', default=False, help='Print YARA strings')
    (options, args) = oParser.parse_args()

    if len(args) > 1:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return
    elif len(args) == 0:
        OLEDump('', options)
    else:
        OLEDump(args[0], options)

if __name__ == '__main__':
    Main()
