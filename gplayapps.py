#!/usr/bin/env python
# -*- coding: utf-8 -*-

################################################################################
#
# Copyright (c) 2011-2012, Hu Wenjun (mindmac.hu@gmail.com)
#
# Ministry of Education Key Lab For Intelligent Networks and Network Security
# BotNet Team
# 
# RunnerThread is a system to detect Android APK's Vulnerabilities, Now it can check 
# 
# the apk if extra permissions are used,if can be repackaged and if there are  
# 
# exposed components 
#
# This module is used to extracted package name and sha1 of digital signature 
# of apks crawled form google play
################################################################################

import os
import shutil
import time
from database.dbprocessor import DBProcessor

from androguard.core.bytecodes import apk, dvm
from threading import Thread
from multiprocessing import Queue

KEYTOOL_PATH = '/home/santoku/jdk1.7.0_11/bin/keytool'
GOOGLE_PLAY_SRC = '/home/santoku/GooglePlay/GooglePalyCrawler/GooglePlay'
GOOGLE_PLAY_DST = '/home/santoku/GooglePlayApps'
CERT_DIR = r'/home/santoku/workspace/SandDroid/SandDroidDecompress'

SLEEP = 24*60*60

SQL_SERVER = '127.0.0.1'
SQL_USER = 'sanddroid'
SQL_PWD = 'mindmac'
SQL_DB = 'sanddroid'

class GPlayApps(Thread):
    def __init__(self, apkPath):
        Thread.__init__(self)
        
        self.apkPath = apkPath
        
        self.apk = None
        self.package = None
        self.sha1 = None
        
        self.dbProcessor = None
        
    def getInfo(self):
        if not os.path.exists(self.apkPath):
            print '%s not exists!' % self.apkPath
        else:
            try:
                self.apk = apk.APK(self.apkPath, KEYTOOL_PATH)
                self.package = self.apk.get_package()
                self.sha1 = self.apk.cert['SHA1']
                certPath = os.path.join(CERT_DIR, self.apk.getMd5Hash().upper())
                shutil.rmtree(certPath)
            except Exception,e:
                print e
                
    def storeIntoDatabase(self):
        try:
            self.dbProcessor = DBProcessor(SQL_SERVER, SQL_USER,SQL_DB, SQL_PWD)
            self.dbProcessor.connect()
            sqlStr = "select count(*) from gplayapps where package_name='%s'" % self.package
            res = self.dbProcessor.query(sqlStr)
            count = res[0][0]
            
            if count==0:
                sqlStr = "insert into gplayapps (package_name, sha1) values ('%s','%s')" % (self.package, self.sha1)
                self.dbProcessor.insert(sqlStr)
        except Exception,e:
            print e
            
    def run(self):
        self.getInfo()
        if self.package is not None and self.sha1 is not None:
            print 'Stroe %s into database...' % self.package
            self.storeIntoDatabase()
            
class FileFetcher(Thread):
    def __init__(self, queue, apkDir):
        Thread.__init__(self)
        
        self.queue = queue
        self.apkDir = apkDir
        
    def run(self):
        while True:
            if self.queue.qsize() < 1000:
                for root, dir, apkfiles in os.walk(self.apkDir):
                    for apkfile in apkfiles:
                        apkAbsPath = os.path.join(root, apkfile)
                        self.queue.put(apkAbsPath)

                    
#                       apkDir = os.path.join(GOOGLE_PLAY_DST,apkfile)
#                       shutil.copy(apkAbsPath, apkDir)
#                       os.remove(apkAbsPath)
            else:
                time.sleep(5*60)
        time.sleep(SLEEP)
        
if __name__ == '__main__':
    
    queue = Queue()
    
    fileFetcher = FileFetcher(queue, GOOGLE_PLAY_SRC)
    fileFetcher.start()
    
    while True:
        for i in range(10):
            apkAbsPath = queue.get()
            gplayapps = GPlayApps(apkAbsPath)
            gplayapps.start()
            
            time.sleep(5)
        
                
    
        
