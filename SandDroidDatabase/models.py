#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Model for the database

from sqlalchemy import create_engine, Table,ForeignKey, Column, Integer, String, Text, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, backref


Base = declarative_base()

class DataModel:
    def __init__(self, db_usr, db_pswd, db_host, db_port, db_name):
        self.db_usr = db_usr
        self.db_pswd = db_pswd
        self.db_host = db_host
        self.db_port = db_port
        self.db_name = db_name
        
    def __initDbModel(self, isEcho=False):
        engine = create_engine("mysql+pymysql://%s:%s@%s:%s/%s?charset=utf8" 
                       % (self.db_usr, self.db_pswd, self.db_host,
                          self.db_port, self.db_name), pool_recycle=3600,
                       echo=isEcho)
        
        return engine
        
    def createSession(self, isEcho=False):
        engine = self.__initDbModel(isEcho)
        Session = sessionmaker(bind=engine)
        #session = Session()
        return Session
        

# many-to-many relationship between apk and permission, ad
   
apk_permission = Table('apk_permission', Base.metadata, 
                        Column('apk_id', Integer, ForeignKey('apk.id')),
                        Column('permission_id', Integer, ForeignKey('permission.id')))

apk_ad = Table('apk_ad', Base.metadata, 
                Column('apk_id', Integer, ForeignKey('apk.id')),
                Column('ad_id', Integer, ForeignKey('ad.id')))

apk_maltype = Table('apk_maltype', Base.metadata, 
                    Column('apk_id', Integer, ForeignKey('apk.id')),
                    Column('maltype_id', Integer, ForeignKey('maltype.id')))

apk_apptype = Table('apk_apptype', Base.metadata, 
                    Column('apk_id', Integer, ForeignKey('apk.id')),
                    Column('apptype_id', Integer, ForeignKey('apptype.id')))

apk_threat = Table('apk_threat', Base.metadata, 
                    Column('apk_id', Integer, ForeignKey('apk.id')),
                    Column('threat_id', Integer, ForeignKey('threat.id')))

class ThreatType:
    MAY_SEND_SMS = 'may_send_sms'
    SEND_SMS = 'send_sms'
    INTERNET = 'data_internet'
    REPACKAGED = 'repackaged'
    REBOOT = 'reboot'
    C2DM = 'c2dm'
    DATA_LEAK = 'data_leak'
    
# APK information
class APK(Base):
    __tablename__ = 'apk'
    id = Column(Integer, primary_key=True)

    #added by songalee at 20170724
    check_time = Column(String(32))
    print('__________check_time added by songalee')

    file_md5 = Column(String(32))
    application_name = Column(String(128))
    version_code = Column(String(8))
    repackaged = Column(Boolean, default=False)
    
    file_name = Column(String(128))
    size = Column(String(16))
    pkg_name = Column(String(128))
    
    cluster_id = Column(Integer)
    manifest_md5 = Column(String(32))
    
    developer = Column(String(32))
    min_sdk = Column(String(4))
    target_sdk = Column(String(4))
    
    remark = Column(String(32))
    last_up_time = Column(DateTime)
    
    app_types = relationship('AppType', secondary=apk_apptype, backref='apk')
    malware_types = relationship('MalwareType', secondary=apk_maltype, backref='apk')
    risk_score = Column(String(8), default='0.00')
    
    # manually review finished
    manual_review = Column(Boolean, default=False)
    
    # sanddroid analyzed 
    analyzed = Column(Boolean, default=False)
    
    # analysis time
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    
    # code features
    native_used = Column(Boolean, default=False)
    dynamic_used = Column(Boolean, default=False)
    reflection_used = Column(Boolean, default=False)
    crypto_used = Column(Boolean, default=False)
    
    # APK's features
    features = relationship('Features', uselist=False, backref='apk')
    
    # static analysis information
    threats = relationship('Threat', secondary=apk_threat, backref='apk')
    signature = relationship('Signature', uselist=False, backref='apk')
    permissions = relationship('Permission', secondary=apk_permission, backref='apk')
    classifications = relationship('Classification', backref='apk')
    
    activities = relationship('Activity', backref='apk')
    services = relationship('Service', backref='apk')
    receivers = relationship('Receiver', backref='apk')
    content_providers = relationship('ContentProvider', backref='apk')
    
    sensitive_apis = relationship('SensitiveAPI', backref='apk')
    sensitive_strs = relationship('SensitiveStr', backref='apk')
    urls = relationship('Url', backref='apk')
    ads = relationship('Ad', secondary=apk_ad, backref='apk')
    
    #virustotal by szhao
    virustotal = relationship('VirusTotal', uselist=False, backref='apk')
    
    # dynamic analysis information
    file_operations = relationship('FileOperation', backref='apk')
    net_operations = relationship('NetOperation', backref='apk')
    encryptions = relationship('Encryption', backref='apk')
    started_services = relationship('StartedService', backref='apk')
    data_leaks = relationship('DataLeak', backref='apk')
    calls = relationship('Call',backref='apk')
    text_msgs = relationship('Sms', backref='apk')
    dexloaders = relationship('DexLoader', backref='apk')
    
    
# ---------------------- Malware Type ------------------------------
class MalwareType(Base):
    __tablename__ = 'maltype'
    id = Column(Integer, primary_key=True)
    name = Column(String(256))
    used_count = Column(Integer, default=0)
    
# ---------------------- App Type ------------------------------
class AppType(Base):
    __tablename__ = 'apptype'
    id = Column(Integer, primary_key=True)
    name = Column(String(256))
    used_count = Column(Integer, default=0)
    
# ---------------------- Static Analysis ---------------------------
class Threat(Base):
    __tablename__ = 'threat'
    id = Column(Integer, primary_key=True)
    type = Column(String(32))
    
class Features(Base):
    __tablename__ = 'features'
    id = Column(Integer, ForeignKey('apk.id'), primary_key=True)
    feature1 = Column(Text)
    feature2 = Column(Text)
    feature3 = Column(Text)
    
class Permission(Base):
    __tablename__ = 'permission'
    id = Column(Integer, primary_key=True)
    name = Column(String(128))
    threat = Column(Integer)
    description = Column(Text)
    used_count = Column(Integer, default=0)
   
class Signature(Base):
    __tablename__ = 'signature'
    id = Column(Integer, ForeignKey('apk.id'), primary_key=True)
    sha1 = Column(String(40))
    country = Column(String(64))
    company_name = Column(String(64))
    location = Column(String(64))
    organization = Column(String(64))
    organization_unit = Column(String(64))
    state = Column(String(64))

#VirusTotal by szhao
class VirusTotal(Base):
    __tablename__ = 'virustotal'
    id = Column(Integer, primary_key=True)
    scanned = Column(Integer)
    file_md5 = Column(String(32),ForeignKey('apk.file_md5'))
    AntiyAVL = Column(String(100))
    Kaspersky = Column(String(100))
    ESETNOD32 = Column(String(100))
    AVG = Column(String(100))
    Symantec = Column(String(100))
    
  
# classify information
class Classification(Base):
    __tablename__ = 'classification'
    id = Column(Integer, primary_key=True)
    apk_id = Column(Integer, ForeignKey('apk.id'))
    name = Column(String(16))
    map = Column(String(8))
    network = Column(String(8))
    normal = Column(String(8))
    system = Column(String(8))
    camera = Column(String(8))
    callsms = Column(String(8))
    
    
# Android Components  
class Activity(Base):
    __tablename__ = 'activity'
    id = Column(Integer, primary_key=True)
    apk_id = Column(Integer, ForeignKey('apk.id'))
    name = Column(String(256))
    main_activity = Column(Boolean, default=False)
    exposed = Column(Boolean, default=False)
    
class Service(Base):
    __tablename__ = 'service'
    id = Column(Integer, primary_key=True)
    apk_id = Column(Integer, ForeignKey('apk.id'))
    name = Column(String(256))
    exposed = Column(Boolean, default=False)
    
class Receiver(Base):
    __tablename__ = 'receiver'
    id = Column(Integer, primary_key=True)
    apk_id = Column(Integer, ForeignKey('apk.id'))
    name = Column(String(256))
    exposed = Column(Boolean, default=False)
    
class ContentProvider(Base):
    __tablename__ = 'content_provider'
    id = Column(Integer, primary_key=True)
    apk_id = Column(Integer, ForeignKey('apk.id'))
    name = Column(String(256))
    exposed = Column(Boolean, default=False)
    
# Interesting Strings
class SensitiveAPI(Base):
    __tablename__ = 'sensitive_api'
    id = Column(Integer, primary_key=True)
    apk_id = Column(Integer, ForeignKey('apk.id'))
    name = Column(String(256))
    short_desc = Column(String(256))

class SensitiveStr(Base):
    __tablename__ = 'sensitive_str'
    id = Column(Integer, primary_key=True)
    apk_id = Column(Integer, ForeignKey('apk.id'))
    name = Column(String(256))
    short_desc = Column(String(256))
    
class Url(Base):
    __tablename__ = 'url'
    id = Column(Integer, primary_key=True)
    apk_id = Column(Integer, ForeignKey('apk.id'))
    name = Column(Text)
    
class Ad(Base):
    __tablename__ = 'ad'
    id = Column(Integer, primary_key=True)
    name = Column(String(256))
    link = Column(String(128))
    used_count = Column(Integer, default=0)
    

# --------------------------- dynamic analysis ---------------------------------
class FileOperation(Base):
    __tablename__ = 'file_operation'
    id = Column(Integer, primary_key=True)
    apk_id = Column(Integer, ForeignKey('apk.id'))
    type = Column(String(16))
    path = Column(Text)
    data = Column(Text)
    
class NetOperation(Base):
    __tablename__ = 'net_operation'
    id = Column(Integer, primary_key=True)
    apk_id = Column(Integer, ForeignKey('apk.id'))
    type = Column(String(16))
    host = Column(String(128))
    port = Column(String(8))
    data = Column(Text)
    
class Encryption(Base):
    __tablename__ = 'encryption'
    id = Column(Integer, primary_key=True)
    apk_id = Column(Integer, ForeignKey('apk.id'))
    key = Column(Text)
    algo = Column(String(16))
    type = Column(String(16))
    data = Column(Text)
    
class StartedService(Base):
    __tablename__ = 'started_service'
    id = Column(Integer, primary_key=True)
    apk_id = Column(Integer, ForeignKey('apk.id'))
    name = Column(String(128))
    
class DataLeak(Base):
    __tablename__ = 'dataleak'
    id = Column(Integer, primary_key=True)
    apk_id = Column(Integer, ForeignKey('apk.id'))
    type = Column(String(16))
    tag = Column(Text)
    dest = Column(Text)
    data = Column(Text)
    
class Call(Base):
    __tablename__ = 'call'
    id = Column(Integer, primary_key=True)
    apk_id = Column(Integer, ForeignKey('apk.id'))
    number = Column(String(16))
    
class Sms(Base):
    __tablename__ = 'sms'
    id = Column(Integer, primary_key=True)
    apk_id = Column(Integer, ForeignKey('apk.id'))
    number = Column(String(16))
    msg = Column(Text)
    
class DexLoader(Base):
    __tablename__ = 'dexloader'
    id = Column(Integer, primary_key=True)
    apk_id = Column(Integer, ForeignKey('apk.id'))
    name = Column(String(64))
    path = Column(Text)
    
    
    
# ---------------------------- user authentication -----------------------------             
class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    name = Column(String(64))
    email = Column(String(64))
    pswd = Column(String(64))
    salt = Column(String(32))
    ip_list = relationship('IP', backref='user')
    
class IP(Base):
    __tablename__ = 'ip'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    ip_addr = Column(String(16))
    
class RegistrationCode(Base):
    __tablename__ = 'registration_code'
    id = Column(Integer, primary_key=True)
    code = Column(String(16))
    used = Column(Boolean, default=False)
    
    def __init__(self, code):
        self.code = code

class FileRepo(Base):
    __tablename__ = 'file_repo'
    
    id = Column(Integer, primary_key=True)
    md5 = Column(String(32))
    src = Column(String(32))
    broken = Column(Boolean, default=False)
    analyzed = Column(Boolean, default=False)

#-------------------------------- repackage ---------------------------------
class ApkCert(Base):
    __tablename__ = 'apk_cert'
    id = Column(Integer, primary_key=True)
    package_name = Column(Text)
    sha1 = Column(String(40))
       
#Base.metadata.create_all(engine)
    
    







