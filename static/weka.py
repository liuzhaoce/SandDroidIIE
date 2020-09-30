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
import shutil
import subprocess

from utils.common import Logger


#===============================================================================
# Class Weka
#===============================================================================
class Weka():
    """
    Class to classify APK file use weka API based on permissions
    """
    def __init__(self, thePermissions, theWekaPath, theArffFile, theArffTemplate, theModelsDir, theOutFile, theLogger=Logger()):
        
        self.permissions = thePermissions
        
        self.wekaPath = theWekaPath
        self.arffFile = theArffFile
        self.arffTemplate = theArffTemplate
        self.outFile = theOutFile
        self.modelsDir = theModelsDir
        
        self.log = theLogger
        
        
    def generateARFF(self):
        """
        Generate ARFF file to classify with weka
        """

            
        instanceAttributes = []
        instanceDatas = []
        
        try:
            arffTemplate = open(self.arffTemplate, 'r')
        except IOError:
            ex = traceback.format_exc()
            self.log.exce(ex)
        try:
            line = arffTemplate.readline()
            while line:
                if line.startswith('@attribute'):
                    index1 = line.find("'")
                    line = line[index1+1 : ]
                    index2 = line.find("'")
                    attribute = line[: index2]
                    if attribute != 'CLASS':
                        instanceAttributes.append(attribute) 
                line = arffTemplate.readline()
        except IOError:
            ex = traceback.format_exc()
            self.log.exce(ex)
        finally:
            arffTemplate.close()
        
        instanceDatas = ['0' for i in instanceAttributes]

        for permission in self.permissions:
            if permission.startswith('android.permission.'):
                permission = permission.replace('android.permission.','')
                if permission in instanceAttributes:
                    index = instanceAttributes.index(permission)
                    instanceDatas[index] = '1'
                    
        # Write to file
        shutil.copy(self.arffTemplate, self.arffFile)
        
        try:
            arff = open(self.arffFile, 'a+')
        except IOError:
            ex = traceback.format_exc()
            self.log.exce(ex)
        try:
            arff.write(','.join(instanceDatas))
            arff.write(',?')
        except IOError:
            ex = traceback.format_exc()
            self.log.exce(ex)
        finally:
            arff.close()

    def classify(self):
        """
        Use specifial model to classify arff file
        """
        # Error while use wekaArgs = [...]
        #wekaArgs = ['java -jar', wekaPath, '-a', arffFile, '-m', modelsDir, '-o', outFile]
        
        wekaArgs = 'java -jar %s -a %s -m %s -o %s' % (self.wekaPath, self.arffFile, self.modelsDir, self.outFile) 
        wekaProcess = subprocess.Popen(wekaArgs,shell=True,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
        stdOut = wekaProcess.stdout.read()
        stdErr = wekaProcess.stderr.read()
        
        isClassified = False
        
        if stdErr and not stdOut:
            isClassified = False
            self.log.error(stdErr)
        else:
            isClassified = True
        
        return isClassified
            
       
        
        

