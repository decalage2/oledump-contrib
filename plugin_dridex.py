#!/usr/bin/env python

__description__ = 'Dridex plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.2'
__date__ = '2015/02/16'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2015/02/12: start, based on sample 6beaa39b2a1d3d896c5e2fd277c227dd
  2015/02/16: added OlFdL0IOXbF, based on sample f1c80a738722554b91452c59adb2f27d

Todo:
"""

import re

def RoV(InputStringToBeDecrypted):
    strTempText = InputStringToBeDecrypted
    strText = strTempText
    strDecryptedText = ""
    strText = strText[:len(strText) - 4]
    strText = strText[-(len(strText) - 4):]
    strText, nCharSize = Extract_Char_Size(strText)
    strText, nEncKey = Extract_Enc_Key(strText, nCharSize)
    nTextLenght = len(strText)
    for nCounter in range(0, len(strText), nCharSize):
        strChar1 = strText[nCounter:nCounter + nCharSize]
        nChar = aYP(strChar1)
        nChar2 = nChar / nEncKey
        strChar2 = chr(nChar2)
        strDecryptedText = strDecryptedText + strChar2
    return strDecryptedText.strip()

def Extract_Char_Size(strText):
    nLeft = len(strText) / 2
    strLeft = strText[:nLeft]
    nRight = len(strText) - nLeft
    strRight = strText[-nRight:]
    strKeyEnc = strLeft[-2:]
    strKeySize = strRight[:2]
    strKeyEnc = yiK(strKeyEnc)
    strKeySize = yiK(strKeySize)
    nKeyEnc = int(strKeyEnc)
    nKeySize = int(strKeySize)
    nCharSize = nKeySize - nKeyEnc
    strText = strLeft[:len(strLeft) - 2] + strRight[-(len(strRight) - 2):]
    return (strText, nCharSize)

def yiK(cString):
    strTempString = ""
    for strChar1 in cString:
        if strChar1.isdigit():
            strTempString = strTempString + strChar1
        else:
            strTempString = strTempString + "0"
    return strTempString

def aYP(strTempText):
    strText = ""
    strTempText = strTempText.strip()
    for strChar1 in strTempText:
        if strChar1.isdigit():
            strText = strText + strChar1
    return int(strText)

def Extract_Enc_Key(strText, nCharSize):
    strEncKey = ""
    nLenght = len(strText) - nCharSize
    nLeft = nLenght / 2
    strLeft = strText[:nLeft]
    nRight = nLenght - nLeft
    strRight = strText[-nRight:]
    strEncKey = strText[nLeft:nLeft + nCharSize]
    strEncKey = yiK(strEncKey)
    nEncKey = int(strEncKey.strip())
    strText = strLeft + strRight
    return (strText, nEncKey)

def MakePositive(value1, value2):
    while value1 < 0:
        value1 += value2
    return value1

def OlFdL0IOXbF(InputData,NumKey):
    return ''.join([chr(MakePositive(ord(c), 256) - NumKey) for c in InputData])

def ContainsString(listStrings, key):
    for aString in listStrings:
        if key.lower() in aString.lower():
            return True
    return False

class cDridexDecoder(cPluginParent):
    macroOnly = True
    name = 'Dridex decoder'

    def __init__(self, name, stream, options):
        self.streamname = name
        self.stream = stream
        self.options = options
        self.ran = False

    def Analyze(self):
        self.ran = True

        oREString = re.compile(r'"([^"\n]+)"')

        result = []
        for foundString in oREString.findall(self.stream):
            try:
                result.append(RoV(foundString))
            except:
                pass

        if ContainsString(result, 'http'):
            return result

        result = []
        for foundString in oREString.findall(self.stream):
            try:
                result.append(OlFdL0IOXbF(foundString, 61))
            except:
                pass

        if ContainsString(result, 'http'):
            return result
        else:
            return []

AddPlugin(cDridexDecoder)
