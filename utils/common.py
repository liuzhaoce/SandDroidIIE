#!/usr/bin/env python
# -*- coding: utf-8 -*-

################################################################################
#
# Copyright (c) 2011-2012, Hu Wenjun (mindmac.hu@gmail.com)
#
# Ministry of Education Key Lab For Intelligent Networks and Network Security
# BotNet Team
# 
# SEDDroid is a system to detect Android APK's Vulnerabilities, Now it can check 
# 
# the apk if extra permissions are used,if can be repackaged and if there are  
# 
# exposed components 
#
################################################################################

import sys
import datetime
import os
import hashlib
import traceback

# ================================================================================
# SandDroid Enums
# ================================================================================

class TaintLogActionEnum:
    FS_READ_ACTION           = 0x00000001
    FS_READ_DIRECT_ACTION    = 0x00000002
    FS_READV_ACTION          = 0x00000004
    FS_WRITE_ACTION          = 0x00000008
    FS_WRITE_DIRECT_ACTION   = 0x00000010
    FS_WRITEV_ACTION         = 0x00000020

    NET_READ_ACTION          = 0x00000100
    NET_READ_DIRECT_ACTION   = 0x00000200
    NET_RECV_ACTION          = 0x00000400
    NET_RECV_DIRECT_ACTION   = 0x00000800
    NET_SEND_ACTION          = 0x00001000
    NET_SEND_DIRECT_ACTION   = 0x00002000
    NET_SEND_URGENT_ACTION   = 0x00004000
    NET_WRITE_ACTION         = 0x00008000
    NET_WRITE_DIRECT_ACTION  = 0x00010000

    SSL_READ_ACTION          = 0x00020000
    SSL_WRITE_ACTION         = 0x00040000

    SMS_ACTION               = 0x00100000 
    SMS_MULTIPART_ACTION     = 0x00200000 
    SMS_DATA_ACTION          = 0x00400000

    CIPHER_ACTION            = 0x00800000
    ERROR_ACTION             = 0x01000000
    CALL_ACTION              = 0x02000000

    @staticmethod
    def getActionString(theAction):
        if theAction == TaintLogActionEnum.FS_READ_ACTION:
            actionString = 'read'
        elif theAction == TaintLogActionEnum.FS_READ_DIRECT_ACTION:
            actionString = 'readDirect'
        elif theAction == TaintLogActionEnum.FS_READV_ACTION:
            actionString = 'readv'
        elif theAction == TaintLogActionEnum.FS_WRITE_ACTION:
            actionString = 'write'
        elif theAction == TaintLogActionEnum.FS_WRITE_DIRECT_ACTION:
            actionString = 'writeDirect'
        elif theAction == TaintLogActionEnum.FS_WRITEV_ACTION:
            actionString = 'writev'

        elif theAction == TaintLogActionEnum.NET_READ_ACTION:
            actionString = 'read'
        elif theAction == TaintLogActionEnum.NET_READ_DIRECT_ACTION:
            actionString = 'readDirect'
        elif theAction == TaintLogActionEnum.NET_RECV_ACTION:
            actionString = 'recv'
        elif theAction == TaintLogActionEnum.NET_RECV_DIRECT_ACTION:
            actionString = 'recvDirect'
        elif theAction == TaintLogActionEnum.NET_SEND_ACTION:
            actionString = 'send'
        elif theAction == TaintLogActionEnum.NET_SEND_DIRECT_ACTION:
            actionString = 'sendDirect'
        elif theAction == TaintLogActionEnum.NET_SEND_URGENT_ACTION:
            actionString = 'sendUrgentData'
        elif theAction == TaintLogActionEnum.NET_WRITE_ACTION:
            actionString = 'write'
        elif theAction == TaintLogActionEnum.NET_WRITE_DIRECT_ACTION:
            actionString = 'writeDirect'

        elif theAction == TaintLogActionEnum.SSL_READ_ACTION:
            actionString = 'read'
        elif theAction == TaintLogActionEnum.SSL_WRITE_ACTION:
            actionString = 'write'

        elif theAction == TaintLogActionEnum.SMS_ACTION:
            actionString = 'sms'
        elif theAction == TaintLogActionEnum.SMS_MULTIPART_ACTION:
            actionString = 'multipartSms'
        elif theAction == TaintLogActionEnum.SMS_DATA_ACTION:
            actionString = 'dataSms'

        elif theAction == TaintLogActionEnum.CIPHER_ACTION:
            actionString = 'cipher'
        elif theAction == TaintLogActionEnum.ERROR_ACTION:
            actionString = 'error'

        else:
            actionString = 'invalid (%d)' % theAction

        return actionString
    
class TaintTagEnum:
    TAINT_CLEAR        = 0x0
    TAINT_LOCATION    = 0x1       
    TAINT_CONTACTS    = 0x2
    TAINT_MIC           = 0x4
    TAINT_PHONE_NUMBER  = 0x8
    TAINT_LOCATION_GPS  = 0x10
    TAINT_LOCATION_NET  = 0x20
    TAINT_LOCATION_LAST = 0x40
    TAINT_CAMERA        = 0x80
    TAINT_ACCELEROMETER = 0x100
    TAINT_SMS           = 0x200
    TAINT_IMEI          = 0x400
    TAINT_IMSI          = 0x800
    TAINT_ICCID         = 0x1000
    TAINT_DEVICE_SN     = 0x2000
    TAINT_ACCOUNT       = 0x4000
    TAINT_HISTORY       = 0x8000
    TAINT_INCOMING_DATA = 0x10000
    TAINT_USER_INPUT    = 0x20000
    TAINT_MEDIA         = 0x40000

    @staticmethod
    def appendTaintTags(theTag1, theTag2):
        tagInt1 = int(theTag1, 16)
        tagInt2 = int(theTag2, 16)
        tagInt = tagInt1 | tagInt2
        tag = "0x%X" % tagInt
        return tag

    @staticmethod
    def getTaintString(theTag):
        try:
            tagInt = int(theTag, 16)
        except TypeError, typeErr:
            if theTag == 0:
                tagInt = theTag
        tagString = str(theTag) + ' ('
        if tagInt == TaintTagEnum.TAINT_CLEAR:
            tagString += 'No Tag)'
        else:
            if tagInt & TaintTagEnum.TAINT_LOCATION:
                tagString += 'Location, '
            if tagInt & TaintTagEnum.TAINT_CONTACTS:
                tagString += 'Contact, '
            if tagInt & TaintTagEnum.TAINT_MIC:
                tagString += 'Microphone, '
            if tagInt & TaintTagEnum.TAINT_PHONE_NUMBER:
                tagString += 'Phone Number, '
            if tagInt & TaintTagEnum.TAINT_LOCATION_GPS:
                tagString += 'GPS Location, '
            if tagInt & TaintTagEnum.TAINT_LOCATION_NET:
                tagString += 'Net Location, '
            if tagInt & TaintTagEnum.TAINT_LOCATION_LAST:
                tagString += 'Last Location, '
            if tagInt & TaintTagEnum.TAINT_CAMERA:
                tagString += 'Camera, '
            if tagInt & TaintTagEnum.TAINT_ACCELEROMETER:
                tagString += 'Accelerometer, '
            if tagInt & TaintTagEnum.TAINT_SMS:
                tagString += 'SMS, '
            if tagInt & TaintTagEnum.TAINT_IMEI:
                tagString += 'IMEI, '
            if tagInt & TaintTagEnum.TAINT_IMSI:
                tagString += 'IMSI, '
            if tagInt & TaintTagEnum.TAINT_ICCID:
                tagString += 'ICCID, '
            if tagInt & TaintTagEnum.TAINT_DEVICE_SN:
                tagString += 'Device SN, '
            if tagInt & TaintTagEnum.TAINT_ACCOUNT:
                tagString += 'Account ,'  
            if tagInt & TaintTagEnum.TAINT_HISTORY:
                tagString += 'History, '
            if tagInt & TaintTagEnum.TAINT_INCOMING_DATA:
                tagString += 'Incoming, '
            if tagInt & TaintTagEnum.TAINT_USER_INPUT:
                tagString += 'UserInput, '
            if tagInt & TaintTagEnum.TAINT_MEDIA:
                tagString += 'Media, '
        if tagString[-2:] == ') ':
            tagString = tagString[:-2]
        elif tagString[-2:] == ', ':
            tagString = tagString[:-2] + ')'
        return tagString
    
# ================================================================================
# SandDroid Logger
# ================================================================================

class LogLevel:
    DEV = 0
    DEBUG = 1
    INFO = 2
    ERROR = 3

class LogMode:
    DEFAULT = 0
    ARRAY = 1
    FILE = 2

class ArrayLogFile:
    def __init__(self):
        self.logEntries = []

    def write(self, theMsg):
        self.logEntries.append(theMsg)

class Logger:
    def __init__(self, theLevel=LogLevel.DEBUG, theMode=LogMode.DEFAULT, theLogFile=None, thePrintAlwaysFlag=False):
        self.level = theLevel
        self.mode = theMode
        self.logFile = theLogFile
        self.printAlwaysFlag = thePrintAlwaysFlag

        if theMode == LogMode.DEFAULT:
            self.log = sys.stdout
        elif theMode == LogMode.FILE:
            if theLogFile is None:
                raise ValueError('Log file is not set')
            self.log = open(theLogFile, 'a', 0)            
        elif theMode == LogMode.ARRAY:
            self.log = ArrayLogFile()

    def getLevel(self):
        return self.level

    def getLogEntries(self):
        if self.mode == LogMode.ARRAY:
            return self.log.logEntries
        else:
            return []

    def isDebug(self):
        return self.level <= LogLevel.DEBUG

    def dev(self, theMsg, setTime=True):
        if self.level <= LogLevel.DEV:
            if setTime:
                dateTime = datetime.datetime.now()
                self.__writeInternal(theMsg, dateTime=dateTime)
            else:
                self.__writeInternal(theMsg)
        
    def debug(self, theMsg, setTime=True):
        if self.level <= LogLevel.DEBUG:
            if setTime:
                dateTime = datetime.datetime.now()
                self.__writeInternal(theMsg, dateTime=dateTime)
            else:
                self.__writeInternal(theMsg)

    def info(self, theMsg, setTime=True):
        if self.level <= LogLevel.INFO:
            if setTime:
                dateTime = datetime.datetime.now()
                self.__writeInternal(theMsg, dateTime=dateTime)
            else:
                self.__writeInternal(theMsg)
                
    def exce(self, theMsg):
        dateTime = datetime.datetime.now()
        self.__writeInternal('Exception: %s' % theMsg, dateTime=dateTime)
        
    def error(self,theMsg):
        dateTime = datetime.datetime.now()
        self.__writeInternal('Error: %s' % theMsg, dateTime=dateTime)        
            
    def write(self, theMsg, setTime=True):
        if setTime:
            dateTime = datetime.datetime.now()
            self.__writeInternal(theMsg,dateTime=dateTime)
        else:
            self.__writeInternal(theMsg)

    def __writeInternal(self, theMsg, dateTime=None):
        try:
            if dateTime is not None:
                self.log.write('%s %s : %s\n' % (Utils.getLogDateAsString(dateTime),Utils.getLogTimeAsString(dateTime),theMsg))
            else:
                self.log.write(' %s\n' % theMsg)  
            if self.printAlwaysFlag:
                print '%s  :%s' %(Utils.getLogTimeAsString(datetime.datetime.now()),theMsg)
        except IOError:
            print traceback.format_exc()
            
            
# ================================================================================
# SandDroid  Utils Class
# ================================================================================

class Utils:
    @staticmethod
    def calcMD5Hash(file):
        """
        Return the MD5 Hash of the file.
        """
        md5 = hashlib.md5()
        return Utils.calcHash(md5, file)
    
    @staticmethod
    def calcHash(theAlg, file):
        blockSize = 2**16
        apkFile = open(file, "r")
        while True:
            data = apkFile.read(blockSize)
            if not data:
                break
            theAlg.update(data)
        return theAlg.hexdigest()
    
    @staticmethod
    def getEmulatorPath(theSdkPath):
        if theSdkPath == '':
            return ''
        else:
            return os.path.join(theSdkPath, 'tools')

    @staticmethod
    def getAdbPath(theSdkPath):
        if theSdkPath == '':
            return ''
        else:
            return os.path.join(theSdkPath,'platform-tools')

    @staticmethod
    def getAaptPath(theSdkPath):
        if theSdkPath == '':
            return ''
        else:
            return os.path.join(theSdkPath, 'platform-tools')

    @staticmethod
    def addSlashToPath(thePath):
        if thePath is None or thePath == '':
            return ''
        if thePath[len(thePath)-1] != '/':
            return thePath + '/'
        else:
            return thePath

    @staticmethod
    def splitFileIntoDirAndName(thePath):
        if thePath is None: return ['', '']
        if len(thePath.rsplit('/', 1)) == 1:
            return [''].extend(thePath.rsplit('/', 1))
        return thePath.rsplit('/', 1)

    @staticmethod
    def getDateAsString(theDate):
        return "%04d%02d%02d" % (theDate.year, theDate.month, theDate.day)
    
    @staticmethod
    def getLogDateAsString(theDate):
        return "%04d-%02d-%02d" % (theDate.year, theDate.month, theDate.day)
    
    @staticmethod
    def getTimeAsString(theTime):
        return "%02d%02d%02d" % (theTime.hour, theTime.minute, theTime.second)

    @staticmethod
    def getLogTimeAsString(theTime):
        return "%02d:%02d:%02d" % (theTime.hour, theTime.minute, theTime.second)

    @staticmethod
    def _getAppListInDirectory(theDir):
        """
        Returns the list of all .apk files within one directory.
        """
        appList = []
        for root, dirs, files in os.walk(theDir):
            for fileName in files:
                ext = os.path.splitext(fileName)[1]
                ext = ext.lower()
                if ext == '.apk':
                    appList.append(os.path.join(root, fileName))
        return appList


class TaintLogKeyEnum:
    GLOBAL_ACTIVE_KEY          = "tdroid.global.active"
    GLOBAL_SKIP_LOOKUP_KEY     = "tdroid.global.skiplookup"
    GLOBAL_ACTION_MASK_KEY     = "tdroid.global.actionmask"
    GLOBAL_TAINT_MASK_KEY      = "tdroid.global.taintmask"
    FS_LOG_TIMESTAMP_KEY       = "tdroid.fs.logtimestamp"
