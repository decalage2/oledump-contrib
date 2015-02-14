#!/usr/bin/env python

__description__ = 'ADD 1 byte decoder for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2014/12/16'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2014/12/16: start

Todo:
"""

def ParseNumber(number):
    if number.startswith('0x'):
        return int(number[2:], 16)
    else:
        return int(number)

class cADD1Decoder(cDecoderParent):
    name = 'ADD 1 byte decoder'

    def __init__(self, stream, options):
        self.stream = stream
        self.options = options
        if self.options.startswith('-k '):
            self.keyADD1 = ParseNumber(self.options[3:])
        else:
            self.keyADD1 = 0x01

    def Available(self):
        return self.keyADD1 != 0x100

    def Decode(self):
        decoded = ''.join([chr((ord(c) + self.keyADD1) & 0xFF) for c in self.stream])
        self.name = 'ADD 1 byte key 0x%02X' % self.keyADD1
        self.keyADD1 += 1
        return decoded

    def Name(self):
        return self.name

AddDecoder(cADD1Decoder)
