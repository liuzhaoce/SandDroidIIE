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
################################################################################

import datetime
import traceback
import os
import shutil
import time
import subprocess

from utils.common import Logger
from dynamic.emulator_client import EmulatorClient,EmulatorClientError
from dynamic.emulator_telnet_client import GsmState,BatteryPowerState,PermissionToSimulate


class DynamicAnalyzerConst:
    THREAD_JOIN_LONG_TIME = 60
    THREAD_JOIN_SHORT_TIME = 10
    THREAD_SLEEP_LONG_TIME =30
    THREAD_SLEEP_SHORT_TIME = 10
    THREAD_SLEEP_ACTIVITY_TIME = 30
    APP_RUN_TIME = 5
    THREAD_SLEEP_SERVICE_TIME = 1
    THREAD_SLEEP_RECEIVER_TIME = 1
    
    FFMPEG_PATH = 'resources/tools/ffmpeg'
    LOGCAT_REDIRECT_FILE = '/data/local/logcat.log'

class DynamicAnalyzer:
    def __init__(self, decompressPath, avdName, curDir, theLogger = Logger()):
        
        self.decompressPath = decompressPath
        self.avdName = avdName
        
        self.mainDir = curDir
        
        self.log = theLogger
        
        self.emulator = None

        self.logcatRedirectFile = None
            
    def runApp(self, theEmulator, theApkObj):
        """
        Runs the application and does various simulations
        """
        # Clear log
        self.log.info('Clear log')
        theEmulator.clearLog()
        
        # Install app
        self.log.info('- Installing app...')
        
        numRetries = 0
        while True:
            numRetries += 1
            self.log.info('Try %d times to install app' % numRetries)
            try:
                theEmulator.installApp(theApkObj.get_filename())
                break
            except EmulatorClientError, ecErr:
                errorOccuredFlag = True
                if ecErr.getCode() == EmulatorClientError.INSTALLATION_ERROR_ALREADY_EXISTS:
                    break
                if ecErr.getCode == EmulatorClientError.GENERAL_INSTALLATION_ERROR:
                    self.log.error('Can\'t install app!')
                
                elif ecErr.getCode() == EmulatorClientError.INSTALLATION_ERROR_SYSTEM_NOT_RUNNING:
                    if numRetries == 4:
                        self.log.info('Number of maximum retries reached, abort installation')
                    else:
                        # Wait and retry
                        errorOccuredFlag = False
                        waitTime = numRetries * 10
                        self.log.info('Installation failed as system might not be running. Wait for %dsec and try again' % waitTime)
                        time.sleep(waitTime)
                        continue
                if errorOccuredFlag: # Error occured
                    # Return
                    return False
        
        # Start logcat redirect
        self.logcatRedirectFile = DynamicAnalyzerConst.LOGCAT_REDIRECT_FILE
        theEmulator.startLogcatRedirect(self.logcatRedirectFile, 4096)
        
        # Switch on taint tracking
        theEmulator.changeGlobalTaintLogState('1', True)
        
        # Run main activity
        try:
            mainActivity = theApkObj.get_main_activity()
            if mainActivity:
                self.log.info('Start main activity %s' % mainActivity)
                theEmulator.startActivity(theApkObj.get_package(), mainActivity)
                time.sleep(DynamicAnalyzerConst.THREAD_SLEEP_ACTIVITY_TIME)
            else:
                self.log.info('No MainActivity found!')
        except Exception,ecErr:
            self.log.exce(traceback.format_exc())
        
        # Capture Screen
        rawFile = os.path.join(self.decompressPath, 'raw.tmp')
        destFile = os.path.join(self.decompressPath, 'screenshot')
        ffmpeg = os.path.join(self.mainDir, DynamicAnalyzerConst.FFMPEG_PATH)
        self._captureScreen(theEmulator, rawFile, destFile, ffmpeg)
        
        # Sleep for a little time to capture screen
        time.sleep(2)
        
        self.log.info('Start all services...')
        try:
            for service in theApkObj.get_services():
                self.log.info('Start service %s' % service)
                theEmulator.startService(theApkObj.get_package(), service)
                time.sleep(DynamicAnalyzerConst.THREAD_SLEEP_SERVICE_TIME)
        except EmulatorClientError, ecErr:
            self.log.exce(traceback.format_exc())
        
        self.log.info('Start all receivers...')
        try:
            for receiver in theApkObj.get_receivers():
                self.log.info('Start receiver %s' % receiver)
                theEmulator.startReceiver(theApkObj.get_package(), receiver)
                time.sleep(DynamicAnalyzerConst.THREAD_SLEEP_SERVICE_TIME)
        except EmulatorClientError, ecErr:
            self.log.exce(traceback.format_exc())
            
        return True
            
    def _captureScreen(self, theEmulator, theRawFile, theDestFile, theFfmpeg):
        """
        Capture Screen and save to destFile
        """
        self.log.info('Capture Screen...')
        theEmulator.captureScreen(theDestFile)
        #theEmulator.captureScreenData(theRawFile)
        #if not os.path.exists(theRawFile):
        #    self.log.info('Raw file %s does\'nt exist! Cann\'t use ffmpeg!')
        #else:
        #    self.log.info('Convert raw file to png')
        #    self.screenDataToPNG(theRawFile, theDestFile, theFfmpeg)
            
    def screenDataToPNG(self, rawFile, destFile, ffmpeg):
        """
        Convert raw screen data to png
        """

        args = [ffmpeg, '-vcodec rawvideo', '-f rawvideo', '-pix_fmt rgb565', 
                '-s 320*480', '-i', rawFile, '-f image2', '-vcodec png', '%s.png' % destFile]
        
        # Something tricky here, need args.split(' ')
        args = ' '.join(args)
        try:
            ffmpegProcess = subprocess.Popen(args.split(' '),
                                            stdout=subprocess.PIPE,
                                            stdin=subprocess.PIPE,
                                            stderr=subprocess.PIPE)
            
        except OSError, osErr:
            raise EmulatorClientError('-Failed to run ffmpeg command \'%s\': %s' % (args, osErr.strerror),
                                      theCode=EmulatorClientError.FFMPEG_RUN_ERROR,
                                      theBaseError=osErr)
        except:
            exc = traceback.format_exc()
            self.log.exce(exc)
        retval = ffmpegProcess.communicate()

        #adb.wait()        
        self.log.info('-Result: %s' % str(retval))
        return retval
            
    # ================================================================================
    # Simulations
    # ================================================================================
    def runSimulation(self, theTelnetClient, permissions):
        """
        Run simulations based on permissions used
        """
        for permission in permissions:
            if permission.startswith('android.permission.'):
                permission = permission.replace('android.permission.','')
                if permission in PermissionToSimulate.CALL_PHONE:
                    self._runGsmSimulation(theTelnetClient)
                elif permission in PermissionToSimulate.LOCATION:
                    self._runGeoSimulation(theTelnetClient)
                elif permission in PermissionToSimulate.SMS:
                    self._runSmsSimulation(theTelnetClient)
                elif permission in PermissionToSimulate.BATTERY:
                    self._runPowerSimulation(theTelnetClient)
        
    def _runGsmSimulation(self, theTelnetClient):
        """
        Simulates incoming calls
        """
        
        self.log.info('-GSM simulation' )
    
        theTelnetClient.changeGSMState(GsmState.OFF)
        time.sleep(3)
        theTelnetClient.changeGSMState(GsmState.ON)
        time.sleep(3)
    
        theTelnetClient.call('+8610086')
        time.sleep(1)
        theTelnetClient.acceptCall('+8610086')
        time.sleep(3)
        theTelnetClient.cancelCall('+8610086')
        time.sleep(1)
        
    def _runGeoSimulation(self, theTelnetClient):
        """
        Simulates route in China
        """
        
        self.log.info('-Geo simulation')
        
        theTelnetClient.changeLocation('34.247289', '108.984601')
        time.sleep(3)
        theTelnetClient.changeLocation('34.246584', '108.984601')
        time.sleep(3)
        theTelnetClient.changeLocation('31.336994', '118.358147')
        time.sleep(3)
        
    def _runSmsSimulation(self, theTelnetClient):
        """
        Simulates SMS
        """
        
        self.log.info('-: SMS simulation')
        
        theTelnetClient.sendSms('+8610086', 'Hi,How are you!')
        time.sleep(3)
        theTelnetClient.sendSms('+8610086', 'Fine,Thank you!')
        time.sleep(3)
    
    def _runPowerSimulation(self, theTelnetClient):
        """
        Simulates Power
        """
        
        self.log.info('-Power simulation')

        theTelnetClient.setBatteryPowerState(BatteryPowerState.DISCHARGING)
        time.sleep(1)
        theTelnetClient.setBatteryCapacity(5)
        time.sleep(5)
        theTelnetClient.setBatteryPowerState(BatteryPowerState.CHARGING)
        time.sleep(3)
        theTelnetClient.setBatteryCapacity(75)
        time.sleep(2)
        theTelnetClient.setBatteryCapacity(100)
        time.sleep(2)
        theTelnetClient.setBatteryPowerState(BatteryPowerState.FULL)
        time.sleep(2)
        

