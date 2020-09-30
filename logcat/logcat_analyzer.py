#!/usr/bin/env python
# -*- coding: utf-8 -*-

################################################################################
#
# Copyright (c) 2011-2012, Hu Wenjun (mindmac.hu@gmail.com)
#
# Ministry of Education Key Lab For Intelligent Networks and Network Security
# BotNet Team
# 
# SandDroid is a system to detect Android APK's Vulnerabilities, Now it can check 
# 
# the apk if extra permissions are used,if can be repackaged and if there are  
# 
# exposed components 
#
################################################################################

import json
import traceback

from utils.common import Logger

from logcat_parser import  LogcatParser


# ================================================================================
# Logcat Analyzer Error Obejct
# ================================================================================ 
class LogcatAnalyzerError(Exception):  
    def __init__(self, theValue):
        self.value = theValue

    def __str__(self):
        return repr(self.value)


# ================================================================================
# Logcat Analyzer
# ================================================================================ 
class LogcatAnalyzer:
    def __init__(self, theLogger=Logger()):
        self.log = theLogger
        
        self.logLines = []
        self.logEntryList = []
        self.logcatParser = LogcatParser()

    def setLogFile(self, theFile):
        """
        Sets the log lines from the provided file
        """
        try:
            logFile = open(theFile, 'r')
        except IOError:
            ex = traceback.format_exc()
            self.log.exce(ex)
        
        try:
            line = logFile.readline()
            while line:
                self.logLines.append(line)
                line = logFile.readline()

        except IOError:
            ex = traceback.format_exc()
            self.log.exce(ex)
            
        finally:
            logFile.close()
            
    def setLogString(self, theStr):
        """
        Sets the log lines from the provided string splitted by \r\n
        """
        self.logLines = theStr.split('\r\n')
        self.numControlChars = 0

    def getNumLogEntries(self, theType=None):
        """
        Return the number of log objects.
        extractLogObjects need to be run before.
        If theType is specified only entries of this instance are returned
        """
        if theType is None:
            return len(self.logEntryList)
        else:
            num = 0
            for logEntry in self.logEntryList:
                if isinstance(logEntry, theType):
                    num += 1
            return num
                
    def extractLogEntries(self):
        """
        Extract JSON objects out of the log lines.
        setLogFile(<file>) or setLogString(<string>) need to be run before
        """

        # Extract JSON strings
        self.log.info('Extract JSON string lines...', setTime=True)
        
        for line in self.logLines:
            # Check for entry
            boxLog = line.split('DroidBox:')
            if len(boxLog) > 1:
                jsonString = boxLog[1]
                jsonString = jsonString.strip()
                # To wipe out string like : DroidBox: addTaintFile(41): adding 0x00000400 to 0x00000000 = 0x00000400
                if not jsonString.startswith('{'):
                    continue
                else:
                    try:
                        logEntry = json.loads(self.logcatParser.decode(jsonString))
                        self.logcatParser.parseLogcat(logEntry)
                    except:
                        ex = traceback.format_exc()
                        self.log.exce(ex)
                        continue
                
    
#logcatAnalyzer = LogcatAnalyzer()
#logcatAnalyzer.setLogFile(r'logcat.log')
#logcatAnalyzer.extractLogEntries()

