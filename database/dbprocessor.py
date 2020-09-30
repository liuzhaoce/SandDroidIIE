#!/usr/bin/env python
# -*- coding: utf-8 -*-

################################################################################
#
# Copyright (c) 2011-2012, Hu Wenjun (mindmac.hu@gmail.com)
#
# Ministry of Education Key Lab For Intelligent Networks and Network Security
# BotNet Team
# 
# GooglePlayKeywordCrawler is a tool to crawl no-paid apps' name as key words,
# These key words are used by GoolgPlayCrawler
# 
# 
################################################################################

from models import *
import time

PERMISSION_THREAT = { 'normal': 2,
                      'signature': 7,
                      'signatureOrSystem': 8,
                      'dangerous': 9}

class DBProcessor:
    def __init__(self, session, staticAnalyzer, logcatParser):
        self.session = session
        self.staticAnalyzer = staticAnalyzer
        self.logcatParser = logcatParser
        self.apk = None
        
    def toUnicode(self, encode_str):
        if encode_str:
            return unicode(encode_str, 'utf-8', 'ignore')

    def updateDatabase(self):
        try:
            if self.staticAnalyzer:
                self.createApkDb(self.staticAnalyzer)
                self.addStaticInfo(self.staticAnalyzer)
                if self.logcatParser:
                    self.addDynamicInfo(self.logcatParser)
            if self.apk:
		print('_____________>'+self.apk.file_name)
		print('_____________>'+self.apk.check_time)
                self.session.add(self.apk)
            try:
                self.session.commit()
		print('___________>insert succeed')
            except:
		print('___________>insert failed')
                self.session.rollback()
                raise
            finally:
                self.session.close()
                
        except Exception:
            import traceback
            traceback.print_exc()
    
    def createApkDb(self, staticAnalyzer):
        basicInfo = self.staticAnalyzer.basicInfo
        application_name = self.toUnicode(basicInfo.get('Application'))
        file_name = self.toUnicode(basicInfo.get('FileName'))
       
        self.apk = APK(file_md5=basicInfo.get('FileMD5'), application_name=application_name,
                  version_code=basicInfo.get('VersionCode'), repackaged=staticAnalyzer.isRepackaged,
                  file_name=file_name, size=basicInfo.get('FileSize'),
                  pkg_name=basicInfo.get('Package'), min_sdk=basicInfo.get('MinSDK'),
                  target_sdk=basicInfo.get('TargetSDK'), risk_score=staticAnalyzer.riskValue,
          analyzed=True)
        
        if staticAnalyzer.isRepackaged:
            threat_db = self.session.query(Threat).filter(Threat.type == ThreatType.REPACKAGED).first()
            if not threat_db:
                threat_db = Threat(type=ThreatType.REPACKAGED)
            if threat_db not in self.apk.threats:
                self.apk.threats.append(threat_db)
    
    def addStaticInfo(self, staticAnalyzer):
	#added by songalee at 20170724
	self.addCheckTime()

        # code features
        sensitiveCodes = staticAnalyzer.sensitiveCodes
        self.addCodeFeatures(sensitiveCodes)
        
        # cert
        cert = staticAnalyzer.basicInfo.get('Cert')
        self.addSignature( cert)
        
        # permissions
        permissions = staticAnalyzer.permissions
        self.addPermissions(permissions)
        
        # classification
        classifyInfo = staticAnalyzer.classifyInfo
        self.addClassifications(classifyInfo)
        
        # components
        self.addComponents( staticAnalyzer)
        
        # apis
        sensitiveAPIs = staticAnalyzer.sensitiveAPIs
        self.addAPIs(sensitiveAPIs)
        
        # strs
        sensitiveStrs = staticAnalyzer.sensitiveStrs
        self.addStrs(sensitiveStrs)
        
        # urls
        urls = staticAnalyzer.urls
        self.addUrls(urls)
        
        # ads
        ads = staticAnalyzer.adModules
        self.addAds(ads)
        
    
    
    def addCodeFeatures(self, sensitiveCodes):
        self.apk.native_used = True if sensitiveCodes.get('NATIVE') == 1 else False
        self.apk.dynamic_used = True if sensitiveCodes.get('DYNAMIC') == 1 else False
        self.apk.reflection_used = True if sensitiveCodes.get('REFLECTION') == 1 else False
        self.apk.crypto_used = True if sensitiveCodes.get('CRYPTO') == 1 else False
    
    # added by songalee at 20170722
    def addCheckTime(self):
	timeStr = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
	self.apk.check_time = timeStr

    def addSignature(self, cert):
        sha1 = cert.get('SHA1')
        country = self.toUnicode(cert.get('C'))
        company_name = self.toUnicode(cert.get('CN'))
        location = self.toUnicode(cert.get('L'))
        organization = self.toUnicode(cert.get('O'))
        organization_unit = self.toUnicode(cert.get('OU'))
        state = self.toUnicode(cert.get('ST'))
        signature = Signature(sha1=sha1, country=country, company_name=company_name,
                              location=location, organization=organization, organization_unit=organization_unit ,
                              state=state)
        self.apk.signature = signature
        
    def addPermissions(self, permissions):
        for permission_name, permission_data in permissions.items():
            permission_db = self.session.query(Permission).filter(Permission.name == permission_name).first()
            if permission_db:
                permission_db.used_count += 1
            else:
                permission_db = Permission(name=permission_name, threat=PERMISSION_THREAT.get(permission_data[0]),
                                           description=permission_data[1], used_count=1)
            if permission_name == 'android.permission.SEND_SMS':
                threat_db = self.session.query(Threat).filter(Threat.type == ThreatType.MAY_SEND_SMS).first()
                if not threat_db:
                    threat_db = Threat(type=ThreatType.MAY_SEND_SMS)
                if threat_db not in self.apk.threats:
                    self.apk.threats.append(threat_db)
            if permission_name == 'android.permission.REBOOT':
                threat_db = self.session.query(Threat).filter(Threat.type == ThreatType.REBOOT).first()
                if not threat_db:
                    threat_db = Threat(type=ThreatType.REBOOT)
                if threat_db not in self.apk.threats:
                    self.apk.threats.append(threat_db)
            if permission_name in ['com.google.android.c2dm.permission.RECEIVE',
                                   'com.google.android.c2dm.permission.SEND']:
                threat_db = self.session.query(Threat).filter(Threat.type == ThreatType.C2DM).first()
                if not threat_db:
                    threat_db = Threat(type=ThreatType.C2DM)
                if threat_db not in self.apk.threats:
                    self.apk.threats.append(threat_db)
            
            self.apk.permissions.append(permission_db)
            
    def addClassifications(self, classifyInfo):
        for classification_name, classification_values in classifyInfo.items():
            classification_db = Classification(name=classification_name,
                                               map=classification_values.get('map'),
                                               network=classification_values.get('network'),
                                               normal=classification_values.get('normal'),
                                               system=classification_values.get('system'),
                                               camera=classification_values.get('camera'),
                                               callsms=classification_values.get('callsms'))
            self.apk.classifications.append(classification_db)
            
    def addComponents(self, staticAnalyzer):
        for activity in staticAnalyzer.activities:
            activity_db = Activity(name=activity)
            if activity == staticAnalyzer.mainActivity:
                activity_db.main_activity = True
            if staticAnalyzer.exposedActivities:
                if activity in staticAnalyzer.exposedActivities:
                    activity_db.exposed = True
            self.apk.activities.append(activity_db)
                        
        for service in staticAnalyzer.services:
            service_db = Service(name=service)
            if staticAnalyzer.exposedServices:
                if service in staticAnalyzer.exposedServices:
                    service_db.exposed = True
            self.apk.services.append(service_db)
            
        for receiver in staticAnalyzer.receivers:
            receiver_db = Receiver(name=receiver)
            if staticAnalyzer.exposedReceivers:
                if receiver in staticAnalyzer.exposedReceivers:
                    receiver_db.exposed = True
            self.apk.receivers.append(receiver_db)
            
        for provider in staticAnalyzer.providers:
            provider_db = ContentProvider(name=provider)
            self.apk.content_providers.append(provider_db)
    
    def addAPIs(self, sensitiveAPIs):
        for api, desc in sensitiveAPIs.items():
            sensitive_api = SensitiveAPI(name=api, short_desc=desc)
            self.apk.sensitive_apis.append(sensitive_api)
            
    def addStrs(self, sensitiveStrs):
        # sensitive strings
        for string, desc in sensitiveStrs.items():
            sensitive_str = SensitiveStr(name=string, short_desc=desc)
            self.apk.sensitive_strs.append(sensitive_str)
    
    def addUrls(self, urls):
        # urls 
        for url in urls:
            url_db = Url(name=url)
            self.apk.urls.append(url_db)
    
    def addAds(self, ads):
        # ads
        for ad_pkg, ad_list in ads.items():
            ad_db = self.session.query(Ad).filter(Ad.name==ad_list[0]).first()
            if ad_db:
                ad_db.used_count += 1
            else:
                ad_db = Ad(name=ad_list[0], link=ad_list[1], used_count=1)
                
            self.apk.ads.append(ad_db)
            
            
    def addDynamicInfo(self, logcatParser):
        # started services
        started_services = logcatParser.startedServices
        self.addStartedServices(started_services)
        
        # network
        receive_nets = logcatParser.receivedNets
        open_nets = logcatParser.openedNets
        sent_nets = logcatParser.sentNets
        closed_nets = logcatParser.closedNets
        self.addNetworks(receive_nets, open_nets, sent_nets, closed_nets)
        
        # data leaks
        data_leaks = logcatParser.leakedDatas
        self.addDataLeaks( data_leaks)
        
        # GSM
        calls = logcatParser.phoneCalls
        self.addCalls( calls)
        
        text_msgs = logcatParser.sentSMSs
        self.addTextMsgs(text_msgs)
        
        # dynamic class loaders
        dexloaders = logcatParser.dexClassLoders
        
        # file operations
        file_operations = logcatParser.fileRWs
        self.addFileOperations( file_operations)
        
    def addStartedServices(self, started_services):
        for started_service in started_services:
                started_service_db = StartedService(name=started_service.get('name'))
                self.apk.started_services.append(started_service_db)
            
    
    def addNetworks(self, receive_nets, open_nets, sent_nets, closed_nets):
        if receive_nets or open_nets or sent_nets or closed_nets:
                threat_db = self.session.query(Threat).filter(Threat.type == ThreatType.INTERNET).first()
                if not threat_db:
                    threat_db = Threat(type=ThreatType.INTERNET)
                if threat_db not in self.apk.threats:
                    self.apk.threats.append(threat_db)
                
        for receive_net in receive_nets:
            data = self.toUnicode(receive_net.get('data'))
            port = receive_net.get('srcport')
            host = receive_net.get('srchost')
            
            receive_net_db = NetOperation(type='Receive', host=host, port=port, data=data)
            self.apk.net_operations.append(receive_net_db)
            
        for open_net in open_nets:
            port = open_net.get('destport')
            host = open_net.get('desthost')
            
            open_net_db = NetOperation(type='Open', host=host, port=port)
            self.apk.net_operations.append(open_net_db)
            
        for sent_net in sent_nets:
            data = self.toUnicode(sent_net.get('data'))
            port = sent_net.get('destport')
            host = sent_net.get('desthost')
            
            sent_net_db = NetOperation(type='Sent', host=host, port=port, data=data)
            self.apk.net_operations.append(sent_net_db)
            
        for closed_net in closed_nets:
            port = closed_net.get('destport')
            host = closed_net.get('desthost')
            
            closed_net_db = NetOperation(type='Closed', host=host, port=port)
            self.apk.net_operations.append(closed_net_db)
            
    def addDataLeaks(self, data_leaks):
        if data_leaks:
            threat_db = self.session.query(Threat).filter(Threat.type == ThreatType.DATA_LEAK).first()
            if not threat_db:
                threat_db = Threat(type=ThreatType.DATA_LEAK)
            if threat_db not in self.apk.threats:
                self.apk.threats.append(threat_db)
                
        for data_leak in data_leaks:
            leak_type = data_leak.get('sink')
            tag = data_leak.get('tag')
            if leak_type == 'Network':
                dest = '%s:%s' % (data_leak.get('desthost'), data_leak.get('destport'))
            elif leak_type == 'File':
                dest = ''
            elif leak_type == 'SMS':
                dest = data_leak.get('number')
            data = self.toUnicode(data_leak.get('data'))
            data_leak_db = DataLeak(type=leak_type, tag=tag, dest=dest, data=data)
            self.apk.data_leaks.append(data_leak_db)
            
    def addCalls(self, calls):
        for call in calls:
            number = call.get('number')
            call_db = Call(number=number)
            self.apk.calls.append(call_db)
            
    def addTextMsgs(self, text_msgs):
        if text_msgs:
            threat_db = self.session.query(Threat).filter(Threat.type == ThreatType.SEND_SMS).first()
            if not threat_db:
                threat_db = Threat(type=ThreatType.SEND_SMS)
            if threat_db not in self.apk.threats:
                self.apk.threats.append(threat_db)
            for text_msg in text_msgs:
                number = text_msg.get('number')
                msg = text_msg.get('message')
                text_msg_db = Sms(number=number, msg=msg)
                self.apk.text_msgs.append(text_msg_db)
    
    def addFileOperations(self, file_operations):
        for file_operation in file_operations:
            file_type = file_operation.get('operation')
            path = self.toUnicode(file_operation.get('path'))
            data = self.toUnicode(file_operation.get('data'))
            file_operation_db = FileOperation(type=file_type, path=path, data=data)
            self.apk.file_operations.append(file_operation_db)
                
        
            
        
        
        
                
            
        
