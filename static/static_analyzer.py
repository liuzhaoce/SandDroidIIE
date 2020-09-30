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

import os
import traceback
import json
import subprocess
import re

from subprocess import call
from androguard.core.bytecodes import apk, dvm
from androguard.core.analysis import analysis, ganalysis,risk
from androguard.core import androconf
from elsim.elsign import dalvik_elsign
from static.smali_parser import SmaliParser

from utils.common import Logger
from weka import Weka
from models import *

# ================================================================================
# StaticAnalyzer Const
# ================================================================================
class StaticAnalyzerConst:
    GOOGLE_PLAY_URL = r'https://play.google.com/store/apps/details?id='
    AEGIS_DB = r'resources/tools/aegis/aegiscan'
    AEGIS_SCANNER = r'resources/tools/aegis/scanner.jar'
    BAKSMALI_PATH = r'resources/tools/baksmali.jar'
    #CLOUNDCHECK = r'resources/tools/androidmd5.jar'
    SEARCHMAWARENAME_PATH = r'resources/tools/searchMawareName.jar'
    
    WEKA_PATH = r'resources/tools/Weka.jar'
    ARFF_PATH = r'resources/weka/arff/arff.txt'
    MODELS_DIR = r'resources/weka/models'
    MAWARESLIB_PATH = r'resources/mawaresLib/order_apk.txt'


# ================================================================================
# StaticAnalyzer Class
# ================================================================================
class StaticAnalyzer:
    def __init__(self, apkObj, decompressPath, curDir, theLogger=Logger()):
        
        self.apkObj = apkObj
        self.decompressPath = decompressPath
        self.mainDir = curDir
        self.log = theLogger
        
        self.basicInfo = {}
        self.permissions = {}
        
        self.sensitiveAPIs = {}
        self.sensitiveStrs = {}
        self.adModules = {}
        self.urls = []
                
        self.mainActivity = None
        self.activities = []
        self.services = []
        self.receivers = []
        self.providers = []
        
        self.exposedActivities = []
        self.exposedServices = []
        self.exposedReceivers = []
        
        self.classifyInfo = {}
        
        # Sensitive Codes: Native, dynamic, crypto, refelection
        self.sensitiveCodes = {} 
        
        # Sensitive Files: file suffix doesn't match magic code
        self.sensitiveFiles = {}
        
        self.riskValue = 0
        self.gexfOut = None
        self.malware = None
        
        self.isRepackaged = False
        self.orgAPKUrl = None
        
    def initEnv(self):
        # init the environment to analyze
        dexPath = os.path.join(self.decompressPath, 'classes.dex')
        smaliDir = os.path.join(self.decompressPath, 'smali')
        self.__getSmali(dexPath, smaliDir)
    
    def __getDex(self, dexPath):
        """
        Get dex file from apk
        """
        try:
            dexFile = open(dexPath, 'wb')
        except IOError:
            ex = traceback.format_exc()
            self.log.exce(ex)
        try: 
            dexFile.write(self.apkObj.get_dex())
        except IOError:
            ex = traceback.format_exc()
            self.log.exce(ex)
        finally:
            dexFile.close()
            
    def __getSmali(self, dexPath, smaliDir):
        """
        Call baksmali to get smali files
        """
        self.__getDex(dexPath)
        try:
            call(args=['java', '-jar', os.path.join(self.mainDir, StaticAnalyzerConst.BAKSMALI_PATH),
                       '-b', '-o', smaliDir, dexPath])
        except Exception:
            ex = traceback.format_exc()
            self.log.exce(ex)
            
    def parseSmali(self):
        smaliDir = os.path.join(self.decompressPath, 'smali')
        smaliParser = SmaliParser(smaliDir, self.log)
        smaliParser.parseSmaliFiles()
        
        # get interesting strings
        self.__getSensitiveAPIs(smaliParser)
        self.__getSensitiveStrs(smaliParser)
        self.__getUrls(smaliParser)
        self.__getAdModules(smaliParser)
        
    def __getSensitiveAPIs(self, smaliParser):
        """
        Get sensitive APIs used in the apk
        """
        self.sensitiveAPIs = smaliParser.sensitiveAPIs
        
    def __getSensitiveStrs(self, smaliParser):
        """
        Get sensitive strings used in the apk
        """
        self.sensitiveStrs = smaliParser.sensitiveStrs
        
    
    def __getUrls(self, smaliParser):
        """
        Get urls used in the apk
        """
        self.urls = list(set(smaliParser.urls))
        
    def __getAdModules(self, smaliParser):
        """
        Get Ad modules used in the apk
        """
        self.adModules = smaliParser.adModules 
    
    def getLogger(self):
        return self.log
        
    def getBasicInfo(self):
        """
        Get APK file's basic information
        """
        self.basicInfo['VersionCode'] = self.apkObj.get_androidversion_code()
        self.basicInfo['FileName'] = self.apkObj.get_file_shortname()
        self.basicInfo['FileMD5'] = self.apkObj.getMd5Hash().upper()
        self.basicInfo['FileSize'] = self.apkObj.get_file_size()
        self.basicInfo['Package'] = self.apkObj.get_package()
        self.basicInfo['Application'],self.basicInfo['Icon'] = self.apkObj.get_appname_icon()
        self.basicInfo['MinSDK'] = self.apkObj.get_min_sdk_version()
        self.basicInfo['TargetSDK'] = self.apkObj.get_target_sdk_version()
        self.basicInfo['Cert'] = self.apkObj.get_cert()
        
        # create icon png
        if self.basicInfo['Icon']:
            self.__createIconFile(self.basicInfo['Icon'])
            
    def __createIconFile(self, srcIcon):
        dstIcon = os.path.join(self.decompressPath, 'icon.png')
        try:
            iconFile = open(dstIcon, 'wb')
        except IOError:
            ex = traceback.format_exc()
            self.log.exce(ex) 
        try:
            iconFile.write(self.apkObj.zip.read(srcIcon))
               
        except Exception:
            ex = traceback.format_exc()
            self.log.exce(ex) 
        finally:
            iconFile.close()
        
        self.basicInfo['Icon'] = dstIcon
        
    def getPermissions(self):
        self.permissions = self.apkObj.get_details_permissions()
        
    def getComponents(self):
        """
        Get components including activity, service, receiver and provider
        """
        self.mainActivity = self.apkObj.get_main_activity()
        self.activities = self.apkObj.get_activities()
        self.services = self.apkObj.get_services()
        self.receivers = self.apkObj.get_receivers()
        self.providers = self.apkObj.get_providers()
        
    def getExposedComps(self):
        """
        Get exposed components: activiy, receiver, service
        """
        self.exposedActivities = self.apkObj.get_exposed_components('activity')
        self.exposedReceivers = self.apkObj.get_exposed_components('receiver')
        self.exposedServices = self.apkObj.get_exposed_components('service')

        
    def getSensitiveFiles(self):
        
        fileTypes = self.apkObj.get_files_types()
        
        for apkFile, type in fileTypes.iteritems():
            if type == 'data' or 'ASCII text' in type:
                continue
            fileSuffix = os.path.splitext(apkFile)[-1][1:]
            fileSuffix = fileSuffix.upper()
            tmpType = type.upper()
            
            if fileSuffix not in tmpType:
                fileTypeInfo = [fileSuffix, type]
                self.sensitiveFiles[apkFile] = fileTypeInfo
            
    def classifyByPermission(self):
        """
        Classify apk based on permissions
        """
        wekaPath = os.path.join(self.mainDir, StaticAnalyzerConst.WEKA_PATH)
        arffFile = os.path.join(self.decompressPath, 'weka.arff')
        arffTemplate = os.path.join(self.mainDir,StaticAnalyzerConst.ARFF_PATH)
        modelsDir = os.path.join(self.mainDir, StaticAnalyzerConst.MODELS_DIR)
        outFile = os.path.join(self.decompressPath, 'classify.out')
        
        if not os.path.exists(modelsDir):
            self.log.info('Models directory %s does\'nt exist!' % modelsDir)
            return
        
        weka = Weka(self.apkObj.get_permissions(), wekaPath, arffFile, arffTemplate, modelsDir, outFile, self.log)
        weka.generateARFF()
        
        if weka.classify():
            if not os.path.exists(outFile):
                self.log.info('Classified file %s does\'nt exist!' % outFile)
                return
            try:
                classifyFile = open(outFile, 'r')
            except IOError:
                exc = traceback.format_exc()
                self.log.exce(exc)
            try:
                classifyData = classifyFile.read()
            except IOError:
                exc = traceback.format_exc()
                self.log.exce(exc)
            finally:
                classifyFile.close()
            
            self.classifyInfo = json.loads(classifyData)
            
        else:
            self.log.info('Classify Failed!')
        
    def getRisk(self):
        """
        Use Androrisk in androguard to fuzzy risk
        """
        try:
            ri = risk.RiskIndicator()
            ri.add_risk_analysis( risk.RedFlags() )
            ri.add_risk_analysis( risk.FuzzyRisk() )
            
            res = ri.with_apk(self.apkObj)
            self.riskValue = res['FuzzyRisk']['VALUE']
            self.sensitiveCodes = res['RedFlags']['DEX']
            
        except Exception:
            ex = traceback.format_exc()
            self.log.exce(ex)
        
    def getGexf(self, gexfOut):
        """
        Use Androgexf in androguard to generate graph
        """
        try:
            self.gexfOut = gexfOut
            vm = dvm.DalvikVMFormat( self.apkObj.get_dex() )
    
            vmx = analysis.VMAnalysis( vm )
            gvmx = ganalysis.GVMAnalysis( vmx, self.apkObj )
    
            b = gvmx.export_to_gexf()
            androconf.save_to_disk( b, self.gexfOut)
        except Exception:
            ex = traceback.format_exc()
            self.log.exce(ex)
            
    '''def getMal(self):
        """
            Use Aegislab Scanner to scan sample
        """
        dataBase = os.path.join(self.mainDir, StaticAnalyzerConst.AEGIS_DB)
        scanner = os.path.join(self.mainDir, StaticAnalyzerConst.AEGIS_SCANNER)
        aegisRes = os.path.join(self.decompressPath, 'mal.txt')
        self.malware = None
        try:
            aegisArgs = 'java -jar %s -d %s -s %s -r %s' % (scanner, dataBase, self.apkObj.get_filename(), aegisRes) 
            aegisProcess = subprocess.Popen(aegisArgs,shell=True,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
            stdOut = aegisProcess.stdout.read()
            stdErr = aegisProcess.stderr.read()
            
            if stdOut:
                self.log.info('%s %s' % ('AegisLabScanner StdOut:', stdOut), setTime=True)
            if stdErr:
                self.log.info('%s %s' % ('AegisLabScanner StdErr:', stdErr), setTime=True)
            

            aegisProcess.stdout.close()
            aegisProcess.stderr.close()
              
            if os.path.exists(aegisRes):
                virus = self.__aegisParse(aegisRes)  
                if virus != 'null':
                    self.malware = virus
                else:
                    self.malware = 'None'
                   
        except Exception:
            ex = traceback.format_exc()
            self.log.exce(ex)'''
    def getMal(self):
	'''
	   Use kingroot's cloundcheck to get maware name  @added by songalee at 20170910
	'''
	print 'java', '-jar', os.path.join(self.mainDir, StaticAnalyzerConst.SEARCHMAWARENAME_PATH), ' ', self.apkObj.filename, ' ',os.path.join(self.mainDir, StaticAnalyzerConst.MAWARESLIB_PATH)
	p = subprocess.Popen(['java', '-jar', os.path.join(self.mainDir, StaticAnalyzerConst.SEARCHMAWARENAME_PATH), self.apkObj.filename, os.path.join(self.mainDir, StaticAnalyzerConst.MAWARESLIB_PATH)],stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = False)
	stdout, stderr = p.communicate()
	print "stdout(mawareName):",stdout
	
	self.malware = stdout.replace(':','')
	print("self.malware:",self.malware)
            
    def __aegisParse(self, aegisRes):
        """
            Parse AegisLabScanner result
        """
        regRule = r'VirusName:(\w*)'
        try:
            fObj = open(aegisRes, 'r')
        except IOError,e:
            print e
            
        try:
            data = fObj.read()
        except IOError,e:
            print e
        
        finally:
            fObj.close()
            

        pattern = re.compile(regRule)
        virus = pattern.findall(data)[0]
        
        return virus
            
    # need change
    def checkRepackage(self, session):
        """
        Check apk file if repackaged
        """
        if session:
            try:
                packageName = self.apkObj.get_package()
                if self.apkObj.cert:
                    sha1 = self.apkObj.cert.get('SHA1')
                    if sha1:
                        apkCert = session.query(ApkCert).filter(ApkCert.package_name == packageName).first()
                        if apkCert:
                            orgSha1 = apkCert.sha1
                            if sha1 != orgSha1:
                                self.isRepackaged = True
                                self.orgAPKUrl = '%s%s' % (StaticAnalyzerConst.GOOGLE_PLAY_URL, packageName)
            except Exception:
                ex = traceback.format_exc()
                self.log.exce(ex)
        else:
            return
                        

            
   
        
    
        


        
        
        
        
