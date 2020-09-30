#!/usr/bin/env python
# -*- coding: utf-8 -*-

# parse and generate the global configuration
import os

# The ConfigParser class should be singleton
# There may be more elegant way to implement singleton in Python
# http://stackoverflow.com/questions/31875/is-there-a-simple-elegant-way-to-define-singletons-in-python/33201#33201

UPLOAD_DIR = '/home/mindmac/workspace/SandDroidIIEWeb/samples/upload'
LOG_DIR = '/home/mindmac/workspace/SandDroidIIE/SandDroidLog'
REPORT_DIR = '/home/mindmac/workspace/SandDroidIIEWeb/static/reports'
SUCCESSED_BAK_DIR = '/home/mindmac/workspace/SandDroidIIE/SandDroidSuccessed'
FAILED_BAK_DIR = '/home/mindmac/workspace/SandDroidIIE/SandDroidFailed'
DECOMPRESS_DIR = '/home/mindmac/workspace/SandDroidIIE/SandDroidDecompress'
ANDROID_SDK_DIR = '/usr/share/adt-bundle/sdk'

class Singleton(object):
    _instance = None
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(Singleton, cls).__new__(
                                cls, *args, **kwargs)
        return cls._instance
    
class ConfigParser(Singleton):
    uploadDir = '/home/mindmac/workspace/SandDroidIIEWeb/samples/upload'
    logDir = '/home/mindmac/workspace/SandDroidIIE/SandDroidLog'
    reportDir = '/home/mindmac/workspace/SandDroidIIEWeb/static/reports'
    successedBakDir = '/home/mindmac/workspace/SandDroidIIE/SandDroidSuccessed'
    failedBakDir = '/home/mindmac/workspace/SandDroidIIE/SandDroidFailed'
    decompressDir = '/home/mindmac/workspace/SandDroidIIE/SandDroidDecompress'
    androidSdkDir = '/usr/share/adt-bundle/sdk'
    threadsNum = 1
    
    dbUsr = 'root'
    dbPswd = 'mindmac'
    dbHost = 'localhost'
    dbPort = '3306'
    dbName = 'iieguard'
    
    directories = {UPLOAD_DIR: uploadDir,
                   LOG_DIR: logDir,
                   REPORT_DIR: reportDir,
                   SUCCESSED_BAK_DIR: successedBakDir,
                   FAILED_BAK_DIR: failedBakDir,
                   DECOMPRESS_DIR: decompressDir,
                   ANDROID_SDK_DIR: androidSdkDir
                   }
        
    # generate all the directories if needed
    def generateDirectories(self):
        for directory in self.directories.values():
            if not os.path.exists(directory):
                try:
                    os.makedirs(directory)
                except OSError,e:
                    print e
                    
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
    configParser.generateDirectories()
    print configParser.getDecompressDir()
    print configParser.getFailedBakDir()
    print configParser.getLogDir()
    print configParser.getReportDir()
    print configParser.getSuccessedBakDir()
