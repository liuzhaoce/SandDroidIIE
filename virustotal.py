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
# This module is used to fetch results scaned by VirusTotal :
# https://www.virustotal.com/en/
#
################################################################################

import simplejson
import urllib
import urllib2
import time
import os

from database.dbprocessor import DBProcessor

SQL_SERVER = '127.0.0.1'
SQL_USER = 'root'
SQL_PWD = 'toor'
SQL_DB = 'sanddroid'

VIRUS_URL = "https://www.virustotal.com/vtapi/v2/file/report"
API_KEY = "7d1075e50598fd2c9ce71c74794070a7e00c034d6e3c8e796dea492fd9b722c1"
PRODUCTS = ['Antiy-AVL','Avast','AVG','ESET-NOD32','F-Secure','Kaspersky','Symantec','TrendMicro']

class VirusTotal:
    def __init__(self):
        self.dbProcessor = DBProcessor(SQL_SERVER, SQL_USER,SQL_DB, SQL_PWD)
        self.dbProcessor.connect()
        
    def queryUnScanned(self):
        md5s = []
        try:
            sqlStr = "select md5 from filerecords where virusscanned=0"
            res = self.dbProcessor.query(sqlStr)
            if len(res) == 0:
                return
            else:
                for sigres in res:
                    md5 =  sigres[0]
                    md5s.append(md5)
                    
            return md5s
        except Exception,e:
            print e
                
    def queryVirus(self, md5):
        print 'Process %s ...' % md5
        parameters = {"resource": md5,"apikey": API_KEY}
        try:
            data = urllib.urlencode(parameters)
            req = urllib2.Request(VIRUS_URL, data)
            response = urllib2.urlopen(req)
        except Exception,e:
            print e
            return
            
        try:
            json = response.read()
            json = simplejson.loads(json)
            if json['response_code'] == 1:
                scans = json['scans']
                #insertStr = "update filerecords (AntiyAVL, Avast, AVG, ESETNOD32, FSecure, Kaspersky, Symantec, TrendMicro) values ("
                for product in PRODUCTS:
                    if scans.has_key(product):
                        res = scans[product]['result']
                        if res:
                            product = product.replace('-','')
                            sqlStr = "update filerecords set %s='%s' where md5='%s'" % (product, res, md5)
                            self.dbProcessor.update(sqlStr)

                sqlStr = "update filerecords set virusscanned=1 where md5='%s'" % md5
                self.dbProcessor.update(sqlStr)
                print 'Update database!'
            elif json['response_code'] == 0:
                print '%s not present in VirusTotal' % md5
            elif json['response_code'] == -2:
                print '%s is still in queued' % md5
        except Exception,e:
            print e
            return

                            
                            
virusTotal = VirusTotal()
while True:
    md5s = virusTotal.queryUnScanned()
    for md5 in md5s:
        print os.linesep
        virusTotal.queryVirus(md5)
        time.sleep(10)
        
    time.sleep(24*60*60)
                    

