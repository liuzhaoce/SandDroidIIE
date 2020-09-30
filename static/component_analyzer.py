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

from common import Logger

# ================================================================================
# ComponentAnalyzer Error
# ================================================================================
class ComponentAnalyzerError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        #dateTime = datetime.datetime.now()
        return repr(self.value)
    
#================================================================================
# ComponentAnalyzer Class -- analyze intent exposure and component exposure
#================================================================================
class ComponentAnalyzer():
    def __init__(self, apkObj, theLogger=Logger()):
        
        self.apkObj = apkObj
        
        self.activities = []
        self.staticReceivers = []
        self.services = []
        
        self.log = theLogger
        
    def analyze(self):
        """
        analyze intent exposure and component exposure
        """
        
        self.activities = self.apkObj.get_exposed_components('activity')
        self.staticReceivers = self.apkObj.get_exposed_components('receiver')
        self.services = self.apkObj.get_exposed_components('service')
        
        self.log.info('Analyze exposed components done!', setTime=True)
        
        
    
        
        
        