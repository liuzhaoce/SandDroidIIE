#!/usr/bin/env python
# -*- coding: utf-8 -*-


import simplejson
import urllib
import urllib2
import time
import os
import pymysql

SQL_SERVER = '127.0.0.1'
SQL_USER = 'root'
SQL_PWD = 'mindmac'
SQL_DB = 'sanddroid'

VIRUS_URL = "https://www.virustotal.com/vtapi/v2/file/report"
API_KEY = "e06b3d1ef3c1cfb005ef7fbe831645578eab0d203ed4c48ee4d7b5c6eb7e9596"
PRODUCTS = ['Antiy-AVL','AVG','ESET-NOD32','Kaspersky','Symantec']

class VirusTotal:
    def __init__(self):
        self.conn = pymysql.connect(host=SQL_SERVER,user=SQL_USER,passwd=SQL_PWD,database=SQL_DB)
        self.cursor = self.conn.cursor()
        
    def queryUnScanned(self):
        md5s = []
        try:
            sqlStr = "select file_md5 from virustotal where scanned=0"
            count = self.cursor.execute(sqlStr)
            print 'virustotal unscanned: %d' %count
            if count == 0:
                #copy from apk table
                sqlStr = "select file_md5 from apk where file_md5 not in (select file_md5 from virustotal)"
                count = self.cursor.execute(sqlStr)
                print 'new unscanned file added: %d' %count
                if count == 0:
                    return md5s
                else:
                    res = self.cursor.fetchall()
                    for sigres in res:
                        md5 = sigres[0]
                        sqlStr = "insert into virustotal(file_md5) values('%s')" % md5
                        self.cursor.execute(sqlStr)
                        print 'adding file: %s' %md5
                    self.conn.commit()
            else:
                res = self.cursor.fetchall()
                for sigres in res:
                    md5 =  sigres[0]
                    md5s.append(md5)
            return md5s
        except Exception,e:
            print 'exception:',e
                
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
			    print product, res
                            sqlStr = "update virustotal set %s='%s' where file_md5='%s'" % (product, res, md5)
                            self.cursor.execute(sqlStr)

                sqlStr = "update virustotal set scanned=1 where file_md5='%s'" % md5
                self.cursor.execute(sqlStr)
                self.conn.commit()
                print 'Update database!'
            elif json['response_code'] == 0:
                print '%s not present in VirusTotal' % md5
                sqlStr = "update virustotal set scanned=2 where file_md5='%s'" %md5
                self.cursor.execute(sqlStr)
                self.conn.commit()
            elif json['response_code'] == -2:
                print '%s is still in queued' % md5
        except Exception,e:
            print e
            return

                            
                            

while True:
    virusTotal = VirusTotal()
    md5s = virusTotal.queryUnScanned()
    if len(md5s) == 0:
        time.sleep(30)
        virusTotal.conn.close()
        continue
    else:
        for md5 in md5s:
            print os.linesep
            virusTotal.queryVirus(md5)
            time.sleep(15)
        virusTotal.conn.close()
        time.sleep(60)
                    

