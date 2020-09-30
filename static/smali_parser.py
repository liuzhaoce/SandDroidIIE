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

import traceback
import os
import re

from sensitive_api import SENSITIVEAPI_DESC
from sensitive_str import SENSITIVESTR_DESC
from ad_modules import ADMODULE
from utils.common import Logger



URLS = ['http://','https://','ftp://', 'www.']

# ================================================================================
# SmaliParser Class
# ================================================================================
class SmaliParser():
    """
    parse smali files to get methods, URLs, String...
    """
    def __init__(self, smaliDir, theLogger=Logger()):
        self.smaliDir = smaliDir
        self.smaliFiles = []
        
        self.sensitiveAPIs = {}
        self.sensitiveStrs = {}
        self.adModules = {}
        self.urls = []
        
        self.log = theLogger
        
        
    def __getSmaliFiles(self):
        self.log.info("Get Smali Files...", setTime=True)
        for (root, dirs, files) in os.walk(self.smaliDir):
            for tmpFile in files:
                smaliFile = os.path.join(root, tmpFile)
                rel = os.path.relpath(smaliFile, self.smaliDir)
                if rel.find("annotation") == 0:
                    continue
                ext = os.path.splitext(smaliFile)[1]
                if ext != '.smali':
                    continue
                self.smaliFiles.append(smaliFile)
    
    def __getSensitiveApi(self, line):
        for api, desc in SENSITIVEAPI_DESC.items():
            if (line.find(api) != -1) and (not self.sensitiveAPIs.has_key(api)):
                self.sensitiveAPIs[api] = desc 
                
    def __getSensitiveStr(self, line):
        for str, desc in SENSITIVESTR_DESC.items():
            if (line.find(str) != -1) and (not self.sensitiveAPIs.has_key(str)):
                self.sensitiveStrs[str] = desc
    
    def __getUrl(self, line, pattern):
        if line.find('const-string') != -1:
            line = line.split(", ")[-1]
            line = line.strip('"')
            line = line.rstrip('"')
            for prefix in URLS:
                if line.startswith(prefix):
                    self.urls.append(line)
            ipList = pattern.findall(line)
            if ipList:
                self.urls.extend(ipList)
            
    
    def __getAdModule(self, line):
        for adclass, desc in ADMODULE.items():
            if line.find(adclass) != -1 and (not self.adModules.has_key(adclass)):
                self.adModules[adclass] = desc            
    
                                      
    def parseSmaliFiles(self):
        """
        Parse smali files to get information
        """
        ipRegex = r'[0-9]+(?:\.[0-9]+){3}'
        pattern = re.compile(ipRegex)
        
        # get smali files
        self.__getSmaliFiles()
        
        for smaliFile in self.smaliFiles:    
            try:
                smaliFileObj = open(smaliFile, 'r')
            except IOError:
                ex = traceback.format_exc()
                self.log.exce(ex)  
            try:
                smaliLines = smaliFileObj.readlines()
            except IOError:
                ex = traceback.format_exc()
                self.log.exce(ex)  
            finally:
                smaliFileObj.close()  
                
            for line in smaliLines:
                line = line.strip()
                # Sensitive APIs
                self.__getSensitiveApi(line)
                            
                # Sensitive Strings
                self.__getSensitiveStr(line)
                            
                # Urls
                self.__getUrl(line, pattern)
                
                # Ad modules
                self.__getAdModule(line)