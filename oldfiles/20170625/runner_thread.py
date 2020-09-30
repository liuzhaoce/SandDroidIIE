#!/usr/bin/env python
# -*- coding: utf-8 -*-

################################################################################
#
# Copyright (c) 2011-2012, Hu Wenjun (mindmac.hu@gmail.com)
#
# Ministry of Education Key Lab For Intelligent Networks and Network Security
# BotNet Team
# 
#
################################################################################

import datetime
import traceback
import os
import shutil

from threading import Thread
from subprocess import call

from androguard.core.bytecodes import apk
from utils.common import Logger,Utils
from static.static_analyzer import StaticAnalyzer
from dynamic.dynamic_analyzer import DynamicAnalyzer
from dynamic.emulator_client import EmulatorClient,EmulatorClientError
from logcat.logcat_analyzer import LogcatAnalyzer
from utils.config_parser import ConfigParser
from database.dbprocessor import DBProcessor
from models import *

# ================================================================================
# RunnerThread Const
# ================================================================================
class RunnerThreadConst:
    DECOMPRESS_DIR = 'SandDroidDecompress'
    ORI_IMAGES_DIR = 'resources/images'
    
    # Risk Value Percentage
    RISK_PERT = [0.6, 0.4]
    
    THREAD_JOIN_LONG_TIME = 60
    THREAD_JOIN_SHORT_TIME = 10
    THREAD_SLEEP_LONG_TIME =30
    THREAD_SLEEP_SHORT_TIME = 10
    THREAD_SLEEP_ACTIVITY_TIME = 3
    APP_RUN_TIME = 5

# ================================================================================
# RunnerThread Runner Thread
# ================================================================================
class RunnerThread(Thread):
    def __init__(self, theApkObj, theAvdName, decompressDir, runHeadless, theLogger=Logger()):
        Thread.__init__(self)
        # configParser
        self.configParser = ConfigParser()
        
        self.apkObj = theApkObj
        self.log = theLogger
        self.curDir = os.path.dirname(__file__)
        
        self.staticAnalyzer = None
        self.dynamicAnalyzer = None
        self.logcatAnalyzer = None

        self.startTimeStr = None
        self.endTimeStr = None
        
        self.emulator = None
        self.emulatorPort = 5554
        self.avdName = theAvdName
        self.runHeadless = runHeadless
        
        self.decompressPath = decompressDir
        self.logcatFile = None
        
        self.session = None
        
        self.cancelFlag = False # Flag for canceling run
        
    def checkForCancelation(self):
        """
        Checks for the cancelation flag sent from the main program.
        If cancel flag is set, abort execution by raising KeyboardInterrupt.
        """
        if self.cancelFlag:
            self.log.info('Cancelation flag found, abort thread')
            traceback.print_stack(file=self.log.log)
            raise KeyboardInterrupt
     
    def __getLogcatFilePath(self):
        """
        Generates logcat file name
        """
        return os.path.join(self.decompressPath, 'logcat.log')

    def getLogger(self):
        return self.log
        
    def staticAnalyze(self):
        """
        Static Analysis
        """     
        
        # Static Analyzer
        self.staticAnalyzer = StaticAnalyzer(self.apkObj, self.decompressPath, self.curDir, self.log)
        
        # Init
        self.log.info('Initialization...')
        self.staticAnalyzer.initEnv()

        # Parse smali files
        self.log.info('Parse smali files to get methods, urls...')
        self.staticAnalyzer.parseSmali()
        
        # APK basic information
        self.log.info('Get APK\'s basic information')
        self.staticAnalyzer.getBasicInfo()
        
        # APK permissions used
        self.log.info('Get APK\'s used permissions')
        self.staticAnalyzer.getPermissions()
        
        # APK components used
        self.log.info('Get APK\'s used components')
        self.staticAnalyzer.getComponents()
        
        # APK components exposed
        self.log.info('Get APK\'s exposed components')
        self.staticAnalyzer.getExposedComps()
        
        # APK classifier
        self.log.info('Get APK\'s classifier information')
        self.staticAnalyzer.classifyByPermission()
        
        # APK fuzzy risk value
        self.log.info('Get APK\'s fuzzy risk score')
        self.staticAnalyzer.getRisk()

        # APK gexf graph
        self.log.info('Get APK\'s gexf graph', setTime=True)
        gexfOutFile = os.path.join(self.decompressPath, '%s.gexf' % self.apkObj.getMd5Hash().upper())
        self.staticAnalyzer.getGexf(gexfOutFile)
        
        # APK Malware detection
        self.log.info('Get APK\'s malicious information', setTime=True)
        self.staticAnalyzer.getMal()
        
        # APK repackaged
        self.log.info('Check APK if repackaged', setTime=True)
        self.staticAnalyzer.checkRepackage(self.session)
            
             
    def dynamicAnalyze(self):
        """
        Dynamic Anlysis
        """
        cur_dir = os.path.dirname(__file__)
        imageDir = os.path.join(cur_dir, 'resources', 'images')
        pcapFile = os.path.join(self.decompressPath, '%s.pcap' % self.apkObj.getMd5Hash().upper())
        
        self.dynamicAnalyzer = DynamicAnalyzer(self.decompressPath, self.avdName, self.curDir, self.log)
        
        self.emulator = EmulatorClient(theSdkPath=self.configParser.getAndroidSdkDir(),
                                       thePort=self.emulatorPort,
                                       theImageDir=imageDir,
                                       thePcapFile=pcapFile,
                                       theRunHeadless=self.runHeadless,
                                       theAvdName=self.avdName,
                                       theLogger=self.log)
        
        self.checkForCancelation()  

        # Start emulator
        self.log.info('Start emulator', setTime=True)
        self.emulator.start()
        
        # Run app
        isFinishedRunnig = self.dynamicAnalyzer.runApp(self.emulator, self.apkObj)
        
        # Store logcat file
        if isFinishedRunnig:
            self.log.info('Store logcat file')
            self.emulator.stopLogcatRedirect()
            self.emulator.storeLogcatRedirectFile(self.dynamicAnalyzer.logcatRedirectFile, self.logcatFile)
            
        else:
            self.log.error('Run app failed!')
    
    
    def killEmulator(self):
        if not self.emulator:
            self.emulator.shutDown()
        
    def logcatAnalyze(self, logcatFile):
        """
        Analyze logcat file
        """
        try:
            if not os.path.exists(logcatFile):
                self.log.info('Logcat file %s doesn\'t exist!' %logcatFile)
                return
            else:
                # Build self.logcatAnalyzer
                self.logcatAnalyzer = LogcatAnalyzer(theLogger=self.log)
                self.logcatAnalyzer.setLogFile(logcatFile)
                self.logcatAnalyzer.extractLogEntries()

        except EmulatorClientError, ecErr:
            self.runnerThread.result['errorList'].append(ecErr)
            
    def __createReportDir(self, fileMd5):
        """
        Create report directory to store media files
        """
        apkReportDir = os.path.join(self.configParser.getReportDir(), fileMd5)
        if not os.path.exists(apkReportDir):
            self.log.info('Create apk %s report directory' % apkReportDir)
            try:
                os.makedirs(apkReportDir)  
            except Exception,e:
                print e
        return apkReportDir  
    
    def _storeResources(self, apkReportDir, md5):
        """
        Store resources such as pcap file to report directory
        """
        # Copy files to report directory
        self.log.info(os.linesep)
        self.log.info('Copy files...')
        
        pcapSrc = os.path.join(self.decompressPath, '%s.pcap' % md5)
        if os.path.exists(pcapSrc):
            self.log.info('- Copy %s ' % os.path.basename(pcapSrc))
            pcapDst = os.path.join(apkReportDir, '%s.pcap' % md5)
            shutil.copyfile(pcapSrc, pcapDst)
            
        gexfSrc = os.path.join(self.decompressPath, '%s.gexf' % md5)
        if os.path.exists(gexfSrc):
            self.log.info('- Copy %s ' % os.path.basename(gexfSrc))
            gexfDst = os.path.join(apkReportDir, '%s.gexf' % md5)
            shutil.copyfile(gexfSrc, gexfDst)
            
        iconSrc = os.path.join(self.decompressPath, 'icon.png' )
        if os.path.exists(iconSrc):
            self.log.info('- Copy %s ' % os.path.basename(iconSrc))
            iconDst = os.path.join(apkReportDir, 'icon.png')
            shutil.copyfile(iconSrc, iconDst)
            
        screenSrc = os.path.join(self.decompressPath, 'screenshot.png')
        if os.path.exists(screenSrc):
            self.log.info('- Copy %s ' % os.path.basename(screenSrc))
            screenDst = os.path.join(apkReportDir, 'screenshot.png')
            shutil.copyfile(screenSrc, screenDst)
            
               
    def _doClearWork(self, md5):
        """
        Delete related file and backup apk
        """
        self.log.info(os.linesep)
        
        if os.path.exists(self.decompressPath):
            self.log.info('Delete %s' % self.decompressPath)
            shutil.rmtree(self.decompressPath)
            
        # Remove the apk file to the backup directory
        try:
            #bakupPath = os.path.join(self.mainDir, SandDroidConst.DEFAULT_BAK_DIR)
            bakupPath = self.configParser.getSuccessedBakDir()
            if os.path.exists(self.apkObj.get_filename()):
                if not os.path.exists(bakupPath):
                    os.makedirs(bakupPath)
        
            apkDst = os.path.join(bakupPath, '%s.apk' % md5)
            if not os.path.exists(apkDst):
                self.log.info('Bakup %s.apk APK file' % md5)              
                shutil.copyfile(self.apkObj.get_filename(), apkDst)     
                     
            os.remove(self.apkObj.get_filename())
            
        except:
            exc = traceback.format_exc()
            self.log.exce(exc)
            
    def __calcRiskValue(self):
        """
        Calculate risk value
        """
        
        # Calculate Risk Value
        riskValue = [self.staticAnalyzer.riskValue]
        
        if self.staticAnalyzer.malware == 'None':
            riskValue.append(0)
        else:
            riskValue.append(100)
            
        riskValueTmp = 0
        riskValueAll = 0
        riskValueTmp += riskValue[0] * RunnerThreadConst.RISK_PERT[0]
        riskValueAll += 100 * RunnerThreadConst.RISK_PERT[0]
        
        riskValueTmp += riskValue[1] * RunnerThreadConst.RISK_PERT[1]
        riskValueAll += riskValue[1] * RunnerThreadConst.RISK_PERT[1]
        
        return '%.2f' % (100 * riskValueTmp / riskValueAll)
    
    def __updateDatabase(self):
        """
        Update the database
        """
        self.staticAnalyzer.riskValue = self.__calcRiskValue()
        if self.logcatAnalyzer and self.logcatAnalyzer.logcatParser:
            dbProcessor = DBProcessor(self.session, self.staticAnalyzer, self.logcatAnalyzer.logcatParser)
            try:
                dbProcessor.updateDatabase()
            except Exception,e:
                print e
        
    def closeLog(self):
        self.log.log.close()
       
    def handleThreadResults(self):
        """
        Handle thread results
        """
        self.log.info(os.linesep)
        self.log.info('Handling thread results...')
        
        if not self.endTimeStr:
            endTime = datetime.datetime.now()
            self.endTimeStr = '%s %s' % (Utils.getLogDateAsString(endTime), Utils.getLogTimeAsString(endTime))
            
        fileMd5 = self.apkObj.getMd5Hash().upper()

        # Create report directory
        apkReportDir = self.__createReportDir(fileMd5)  
        
        # Store resources
        self._storeResources(apkReportDir, fileMd5) 
        
        # Do clear work
        self._doClearWork(fileMd5)
    
        # Update Database   
        self.log.info("Update database") 
        self.__updateDatabase()
        
    def run(self):
        """
        Run the thread
        """
        fileMd5 = self.apkObj.getMd5Hash().upper()
        # Log information
        self.log.info('Start thread to analyzing...')
        self.log.info('FileMD5: %s' % fileMd5)
        
        # build database session
        self.log.info('Create SqlAlchemy Session...') 
        dataModel = DataModel(self.configParser.getDbUsr(), self.configParser.getDbPswd(),
                              self.configParser.getDbHost(), self.configParser.getDbPort(),
                              self.configParser.getDbName()
                              )
	self.log.info('=============dbName:'+self.configParser.getDbName())
        try:
            Session = dataModel.createSession(False)
            self.session = Session()
        except Exception,e:
            self.log.exce("Create SqlAlchemy session error %s" % e)
            return
            
        # Run
        try:
            startTime = datetime.datetime.now()
            self.startTimeStr = '%s %s' % (Utils.getLogDateAsString(startTime), 
                                        Utils.getLogTimeAsString(startTime))
                
            self.logcatFile = self.__getLogcatFilePath()
            
            # Static Analysis
            self.checkForCancelation()
            
            self.log.info(os.linesep)
            self.log.info('==Static Analysis...')
            self.staticAnalyze()
            
            # Dynamic Analysis
            self.checkForCancelation()
            
            self.log.info(os.linesep)
            self.log.info('==Dynamic Analysis...')
            self.dynamicAnalyze()
            
            # Shutdown Emulator
            self.log.info('Shutdown emulator %s' % self.avdName)
            self.emulator.shutDown()
            
            # Logcat Analysis
            self.log.info(os.linesep)
            self.log.info('== Analyze Logcat file...')
            self.logcatAnalyze(self.logcatFile )
            
            # End
            endTime = datetime.datetime.now()
            self.endTimeStr = '%s %s' % (Utils.getLogDateAsString(endTime), Utils.getLogTimeAsString(endTime))
            
        except Exception:
            exc = traceback.format_exc()
            self.log.exce(exc)
    
    
        
