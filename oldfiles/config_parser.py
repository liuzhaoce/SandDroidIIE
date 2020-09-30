#!/usr/bin/env python
# -*- coding: utf-8 -*-

# parse and generate the global configuration
import os

# The ConfigParser class should be singleton
# There may be more elegant way to implement singleton in Python
# http://stackoverflow.com/questions/31875/is-there-a-simple-elegant-way-to-define-singletons-in-python/33201#33201

UPLOAD_DIR = 'upload-directory'
LOG_DIR = 'log-directory'
REPORT_DIR = 'report-directory'
SUCCESSED_BAK_DIR = 'successed-back-directory'
FAILED_BAK_DIR = 'failed-back-directory'
DECOMPRESS_DIR = 'decompress-directory'
ANDROID_SDK_DIR = 'android-sdk-directory'

class Singleton(object):
    _instance = None
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(Singleton, cls).__new__(
                                cls, *args, **kwargs)
        return cls._instance
    
class ConfigParser(Singleton):
    uploadDir = None
    logDir = None
    reportDir = None
    successedBakDir = None
    failedBakDir = None
    decompressDir = None
    androidSdkDir = None
    threadsNum = 1
    
    dbUsr = None
    dbPswd = None
    dbHost = None
    dbPort = None
    dbName = None
    
    directories = {UPLOAD_DIR: uploadDir,
                   LOG_DIR: logDir,
                   REPORT_DIR: reportDir,
                   SUCCESSED_BAK_DIR: successedBakDir,
                   FAILED_BAK_DIR: failedBakDir,
                   DECOMPRESS_DIR: decompressDir,
                   ANDROID_SDK_DIR: androidSdkDir
                   }
        
    def parseFile(self, filePath):
	print ('lisong filePath:'+filePath)
	filePath1 = '/home/mindmac/workspace/SandDroidIIE/sanddroid.ini'
	print ('lisong filePath1:'+filePath1)
        if filePath and os.path.exists(filePath1):
            try:
                fileObj = open(filePath, 'r')
            except IOError,e:
                print e
            try:
                lines = fileObj.readlines()
                if lines:
                    self.parseStreams(lines)
            except IOError,e:
                print e
            finally:
                fileObj.close()
	else:
	    print "there are not files!lisong"
                
    def parseStreams(self, lines):
        for line in lines:
            if line.startswith('#') or line == os.linesep:
                continue
            else:
                elems = line.split('=')
                elems = [elem.strip() for elem in elems]
                paramKey = elems[0]
                paramValue = elems[-1]
                if paramKey == 'UPLOAD_DIR':
                    self.directories[UPLOAD_DIR] = self.uploadDir = paramValue
                if paramKey == 'LOG_DIR':
                    self.directories[LOG_DIR] = self.logDir = paramValue
                elif paramKey == 'REPORT_DIR':
                    self.directories[REPORT_DIR] = self.reportDir = paramValue
                elif paramKey == 'SUCCESSED_BAK_DIR':
                    self.directories[SUCCESSED_BAK_DIR] = self.successedBakDir = paramValue
                elif paramKey == 'FAILED_BAK_DIR':
                    self.directories[FAILED_BAK_DIR] = self.failedBakDir = paramValue
                elif paramKey == 'DECOMPRESS_DIR':
                    self.directories[DECOMPRESS_DIR] = self.decompressDir = paramValue
                elif paramKey == 'ANDROID_SDK_DIR':
                    self.directories[ANDROID_SDK_DIR] = self.androidSdkDir = paramValue
                elif paramKey == 'THREADS_NUM':
                    try:
                        self.threadsNum = int(paramValue)
                    except ValueError,e:
                        print e
                elif paramKey == 'DATABASE_USER':
                    self.dbUsr = paramValue
                elif paramKey == 'DATABASE_PSWD':
                    self.dbPswd = paramValue
                elif paramKey == 'DATABASE_HOST':
                    self.dbHost = paramValue
                elif paramKey == 'DATABASE_PORT':
                    self.dbPort = paramValue
                elif paramKey == 'DATABASE_NAME':
                    self.dbName = paramValue
                else:
                    continue
                
        self.generateDirectories()
              
    # generate all the directories if needed
    def generateDirectories(self):
        for directory in self.directories.values():
	#change by songalee
            try:
            	if not os.path.exists(directory):
                	try:
                    		os.makedirs(directory)
                	except OSError,e:
                    		print e
	    except:
		    print "mistakes!"
                    
    def getUploadDir(self):   
        return self.uploadDir
        
    def getLogDir(self):
        return self.logDir
    
    def getReportDir(self):
        return self.reportDir
    
    def getSuccessedBakDir(self):
        return self.successedBakDir
    
    def getFailedBakDir(self):
        return self.failedBakDir
    
    def getDecompressDir(self):
        return self.decompressDir
    
    def getAndroidSdkDir(self):
        return self.androidSdkDir
    
    def getThreadsNum(self):
        return self.threadsNum
    
    def getDbUsr(self):
        return self.dbUsr
    
    def getDbPswd(self):
        return self.dbPswd
    
    def getDbHost(self):
        return self.dbHost
    
    def getDbPort(self):
        return self.dbPort
    
    def getDbName(self):
        return self.dbName
    
    def getDirectoies(self):
        return self.directories
    


    
if __name__ == '__main__':
    path = '/home/mindmac/workspace/SandDroidIIE/sanddroid.ini'
    configParser = ConfigParser()
    configParser.parseFile(path)
    print configParser.getDecompressDir()
    print configParser.getFailedBakDir()
    print configParser.getLogDir()
    print configParser.getReportDir()
    print configParser.getSuccessedBakDir()
