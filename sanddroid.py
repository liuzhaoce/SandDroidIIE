#!/usr/bin/env python
# -*- coding: utf-8 -*-

################################################################################
#
# Copyright (c) 2011-2012, Hu Wenjun (mindmac.hu@gmail.com)
#
# Ministry of Education Key Lab For Intelligent Networks and Network Security
# BotNet Team
# 
# SandDroid is a system to detect Android Malware 
# 
# 
# 
# 
#
################################################################################
import sys
import argparse
import datetime
import time
import os
import traceback
import json
import shutil

from threading import Thread
from sqlalchemy import and_, desc, func

from SandDroidDatabase.models import DataModel
from utils.common import Logger, LogLevel, LogMode, Utils
from androguard.core.bytecodes import apk
from runner_thread import RunnerThread
from utils.config_parser import ConfigParser
from models import *


# ================================================================================
# SandDroid Get APPS Thread (Used in Listen Mode)
# ================================================================================
class AppGettingThread(Thread):
    def __init__(self, sandDroid=None):
        Thread.__init__(self)
        self.sandDroid = sandDroid
        self.appDir = sandDroid.configParser.getUploadDir()

    def run(self):
        try:
            while True:
                appList = os.listdir(self.appDir)
                for appName in appList:
                    appFullPath = os.path.join(self.appDir, appName)
                    if (not appFullPath in self.sandDroid.appList) and (not appFullPath in self.sandDroid.runningApps):
                        self.sandDroid.appList.append(appFullPath)

                time.sleep(SandDroidConst.THREAD_SLEEP_LONG_TIME)

        except Exception:
            ex = traceback.format_exc()
            self.sandDroid.log.exce(ex)


# ================================================================================
# SandDroid Constant
# ================================================================================
class SandDroidConst:
    CONFIG_FILE_PATH = 'sanddroid.ini'

    LONG_PLUS_SIGN = 47 * '+'
    SHORT_PLUS_SIGN = 4 * '+'
    LONG_SPACE = 20 * ' '
    LONG_EQUAL_SIGN = 47 * '='

    THREAD_JOIN_LONG_TIME = 60
    THREAD_JOIN_SHORT_TIME = 10
    THREAD_SLEEP_LONG_TIME = 30
    THREAD_SLEEP_SHORT_TIME = 10
    APP_RUN_TIME = 5
    HEARTBEAT = 3


# ================================================================================
# SandDroid Class
# ================================================================================
class SandDroid():
    def __init__(self, theConfigFilePath, theLogger=Logger()):
        # parse config file
        self.configParser = ConfigParser()
        # self.configParser.parseFile(theConfigFilePath)
        self.configParser.generateDirectories()

        self.log = theLogger

        # keytool path to parse apk's signature
        self.keytoolPath = None

        # sanddroid directories
        self.mainDir = os.path.dirname(__file__)

        self.appList = []  # list to store apk file - full path
        self.runningApps = []  # list to store apk file which in being analyzed

        self.runHeadless = False
        self.emulatorStartPort = 5554

        self.numThreads = 1
        self.maxThreadRuntime = 600

        # control running threads
        self.threadLogFileList = []  # list to store thread log file path
        self.numFinishedApps = 0  # number of analyzed apps
        self.numRunningThreads = 0  # number of running threads
        self.threadList = []  # list of threads, size=numThreads
        self.threadActiveMask = []  # bitmask to determine if thread is active, size=numThreads

        self.avdsheartbeat = (0, 0, 0, 0)  # list avds' times used in one cycle
        self.avdheartbeat = 0
        self.startTime = datetime.datetime.now()

    # ================================================================================
    # Helpers
    # ================================================================================
    def __isConfigValid(self):
        # check configure
        javaHome = os.environ.get('JAVA_HOME')
        if not javaHome:
            self.log.error('Java environment not detected')
            return False
        else:
            keytoolPath = os.path.join(javaHome, 'bin', 'keytool')
            if not os.path.exists(keytoolPath):
                self.log.error('Java keytool no exist')
                return False
            else:
                self.keytoolPath = keytoolPath

        for desc, directory in self.configParser.getDirectoies().items():
            if not directory or not os.path.exists(directory):
                self.log.error('%s doesn\'t exist!' % desc)
                return False

        if (not self.configParser.getDbUsr()) and (not self.configParser.getDbHost()) and (
        not self.configParser.getDbPort()) \
                and (not self.configParser.getDbPswd()) and (not self.configParser.getDbName()):
            return False

        return True

    def _getLogDir(self):
        """
        Get log directory
        """
        logRootDir = self.configParser.getLogDir()
        logDir = '%s/%s-%s' % (logRootDir, Utils.getDateAsString(self.startTime), Utils.getTimeAsString(self.startTime))
        return logDir

    def _createLogDir(self, logDir):
        """
        Create log directory
        """
        if not os.path.exists(logDir):
            try:
                os.makedirs(logDir)
            except OSError, e:
                print e

    def __getThreadLogFile(self, fileMd5):
        """
        Return log file name for app runner thread
        """
        analyzeDateTime = datetime.datetime.now()
        analyzeDate = Utils.getDateAsString(analyzeDateTime)
        analyzeTime = Utils.getTimeAsString(analyzeDateTime)

        logFileName = '%s-%s-%s.log' % (fileMd5, analyzeDate, analyzeTime)

        return logFileName

    def __createThreadLogFile(self, logFileName):
        """
        Create log file for each thread
        """
        logFile = os.path.join(self._getLogDir(), logFileName)
        threadLogger = Logger(theLevel=self.log.level,
                              theMode=LogMode.FILE,
                              theLogFile=logFile)
        return threadLogger

    def _handleThreadResults(self, theRunnerThread):
        """
        Handle thread results
        """
        self.log.info('Handling thread results...')
        self.runningApps.remove(theRunnerThread.apkObj.get_filename())

        theRunnerThread.handleThreadResults()

        theRunnerThread.closeLog()

    def __processFailed(self, apkFile, md5):
        """
        Process APK which is failed analysis
        """
        # Remove the apk file to the backup directory
        try:
            if os.path.exists(apkFile):
                apkDst = os.path.join(self.configParser.getFailedBakDir(), '%s.apk' % md5)
                if os.path.exists(apkDst):
                    self.log.info('Apk %s exsits already' % apkDst)
                else:
                    self.log.info('Bakup %s APK file' % apkFile)
                    shutil.copyfile(apkFile, apkDst)

                os.remove(apkFile)
                self.runningApps.remove(apkFile)
        except OSError:
            exc = traceback.format_exc()
            self.log.exce(exc)

    # Check to see if the file existed, if so, remove
    def __isDbExist(self, session, fileMd5, app):
        apkDb = session.query(app).filter(and_(func.upper(app.file_md5) == fileMd5,
                                               app.analyzed == True)).first()
        # if analyzed, remove
        if apkDb:
            try:
                os.remove(app)
            except OSError, e:
                self.log.error(str(e))
            return True
        else:
            return False

    # check inactive threads
    def __checkInactiveThreads(self, threadIndex):
        for i in xrange(self.numThreads):
            if not self.threadActiveMask[i]:
                threadIndex = i

        return threadIndex

    # build decompress directory
    def __buildDecompressDir(self, fileMd5):
        try:
            decompressDir = os.path.join(self.configParser.getDecompressDir(), fileMd5)
            if not os.path.exists(decompressDir):
                os.makedirs(decompressDir)
        except OSError, e:
            self.log.error(str(e))

        return decompressDir

    def deleteUserDataQemuImg(self, avdName):
        avdfilePath = '/home/mindmac/.android/avd/' + avdName + '.avd/userdata-qemu.img'
        if (os.path.exists(avdfilePath)):
            os.remove(avdfilePath)
            self.log.info('========================delete success:%s' + avdfilePath)
        else:
            self.log.info('========================no such file:%s', "%" + avdfilePath)

            # Build runner thread

    def __buildRunnerThread(self, threadIndex, apkObj, decompressDir, threadLogger):
        avdName = '%s-%s' % ('SandDroid', threadIndex + 1)  # 修改成+2
        self.deleteUserDataQemuImg(avdName)
        '''if(self.avdsheartbeat[threadIndex+1] >= SandDroidConst.HEARTBEAT):
            self.deleteUserDataQemuImg(avdName)
            self.avdheartbeat = 0'''
        # self.avdsheartbeat[threadIndex+1] = 0
        # self.avdsheartbeat[threadIndex+1] += 1
        # self.avdheartbeat +=1
        runnerThread = RunnerThread(apkObj, avdName, decompressDir, self.runHeadless, theLogger=threadLogger)
        runnerThread.emulatorPort = self.emulatorStartPort + threadIndex * 2
        runnerThread.daemon = False
        runnerThread.startTime = datetime.datetime.now()
        self.threadList[threadIndex] = runnerThread
        self.threadActiveMask[threadIndex] = True
        self.numRunningThreads += 1
        return runnerThread

    # check active threads and terminate
    def __doActiveThreads(self):
        # Check for inactive threads
        currentTime = datetime.datetime.now()
        for i in xrange(self.numThreads):
            # Thread terminated regulary
            if self.threadList[i] and not self.threadList[i].isAlive():
                print 'regular teminate'
                self.log.info('Thread %d for %s is finisehd!' % ((i + 1), self.threadList[i].apkObj.get_filename()))
                self._handleThreadResults(self.threadList[i])
                self.numFinishedApps += 1
                self.threadList[i] = None
                self.threadActiveMask[i] = False
                self.numRunningThreads -= 1

            # Check how long thread is running
            elif self.threadList[i]:
                runningTime = currentTime - self.threadList[i].startTime
                if runningTime.seconds > self.maxThreadRuntime:
                    self.log.info('Thread %d for %s is running more than %d sec, cancel' % (
                    (i + 1), self.threadList[i].apkObj.get_filename(), self.maxThreadRuntime))
                    self.threadList[i].cancelFlag = True
                    self.threadList[i].join(SandDroidConst.THREAD_JOIN_LONG_TIME)  # Wait until finished, max 1min
                    if self.threadList[i].isAlive():
                        self.log.error('Thread %d cannot be terminated, anyway free it up.' % ((i + 1)))
                        if self.threadList[i].emulator:
                            self.threadList[i].killEmulator()
                        self.threadList[i].join(SandDroidConst.THREAD_JOIN_SHORT_TIME)
                        self._handleThreadResults(self.threadList[i])
                    else:
                        self.log.info('Thread %d successfully terminated' % ((i + 1)))
                        self._handleThreadResults(self.threadList[i])

                    self.numFinishedApps += 1
                    self.threadList[i] = None
                    self.threadActiveMask[i] = False
                    self.numRunningThreads -= 1

                    # ================================================================================

    # Run
    # ================================================================================
    def run(self):
        """
        Run SandDroid to analyze apk files
        """
        # check configure
        if not self.__isConfigValid():
            return
        else:
            # start getting apps 
            self.log.info('Start AppGettingThread to get apps...')
            appGettingThread = AppGettingThread(self)
            appGettingThread.daemon = False
            appGettingThread.start()

            # Run
            self.log.info('Starting Analyze....')
            self.log.info(SandDroidConst.LONG_EQUAL_SIGN)

            # Inits
            for i in xrange(self.numThreads):
                self.threadList.append(None)
                self.threadActiveMask.append(False)

            # build database session
            dataModel = DataModel(self.configParser.getDbUsr(), self.configParser.getDbPswd(),
                                  self.configParser.getDbHost(), self.configParser.getDbPort(),
                                  self.configParser.getDbName()
                                  )
            try:
                Session = dataModel.createSession(False)
                session = Session()
            except Exception, e:
                print 'Can not create sqlAlchemy session instance'
                return

            while True:
                try:
                    # Get app and start thread
                    if self.numRunningThreads < self.numThreads and len(self.appList):
                        # Get app 
                        app = self.appList.pop(0)

                        fileMd5 = Utils.calcMD5Hash(app).upper()
                        # if self.__isDbExist(session, fileMd5, app):
                        #    continue

                        # Check for inactive thread
                        threadIndex = -1
                        threadIndex = self.__checkInactiveThreads(threadIndex)
                        if threadIndex == -1:
                            self.log.error('No free thread index found even though numRunningThreads < numThreads')
                            continue

                        self.runningApps.append(app)
                        self.log.info(
                            'Free thread found (%d) for analyzing %s' % (threadIndex + 1, os.path.basename(app)))
                        self.log.info('Analyzing %s...' % app)

                        # Determine logger for each thread
                        logFileName = self.__getThreadLogFile(fileMd5)
                        threadLogger = self.__createThreadLogFile(logFileName)
                        self.threadLogFileList.append(logFileName)

                        # build decompress directory
                        decompressDir = self.__buildDecompressDir(fileMd5)

                        try:
                            apkObj = apk.APK(app, self.keytoolPath, decompressDir, threadLogger)
                        except Exception:
                            self.__processFailed(app, fileMd5)
                            ex = traceback.format_exc()
                            self.log.exce(ex)
                            continue

                        if not apkObj.is_valid_APK():
                            self.log.info('%s is an invalid APK file!' % app)
                            self.__processFailed(app, fileMd5)
                            continue
                        apkObj.main_dir = self.mainDir
                        apkObj.md5 = fileMd5

                        # Build thread and start
                        runnerThread = self.__buildRunnerThread(threadIndex, apkObj, decompressDir, threadLogger)
                        runnerThread.start()

                    # No free thread -> check timing
                    else:
                        if len(self.appList):
                            self.log.info('No free thread found, wait for free thread')
                        elif self.numRunningThreads < self.numThreads:
                            self.log.info('Listen to the app folder,waiting...')

                        # Check for active threads
                        self.__doActiveThreads()

                        # Sleep
                        time.sleep(SandDroidConst.THREAD_SLEEP_SHORT_TIME)

                    time.sleep(SandDroidConst.THREAD_SLEEP_LONG_TIME)

                except Exception, e:
                    print e
                    break

            session.close()


# ================================================================================
# main -- Run from here
# ================================================================================
def main():
    parser = argparse.ArgumentParser(description= \
                                         "An APK Analysis SandBox.")
    parser.add_argument('-r, --runHeadless', action='store_true', default=False,
                        dest='runHeadless', help='Run emulator without window.')

    parser.add_argument('-v, --version', action='version',
                        version='SandDroid v0.1beta')

    # args = parser.parse_args([-p','santoku'])
    args = parser.parse_args()

    # SandDroid
    sandDroid = SandDroid(SandDroidConst.CONFIG_FILE_PATH, theLogger=Logger())

    # Set SandDroid
    sandDroid.runHeadless = args.runHeadless
    sandDroid.startTime = datetime.datetime.now()

    # Build logger
    sandDroid._createLogDir(sandDroid._getLogDir())

    logLevel = LogLevel.INFO
    logger = Logger(theLevel=logLevel,
                    theMode=LogMode.FILE,
                    theLogFile='%s/%s-SandDroid-run.log' % (
                    sandDroid._getLogDir(), Utils.getTimeAsString(sandDroid.startTime)),
                    thePrintAlwaysFlag=True)

    sandDroid.log = logger
    sandDroid.run()
    sandDroid.log.log.close()


# ================================================================================
# Start Point
# ================================================================================ 
if __name__ == '__main__':
    time.sleep(5)
    main()
