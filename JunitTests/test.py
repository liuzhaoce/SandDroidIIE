#class SandDroidConst:
#    DEFAULT_LOG_DIR = 'SandDroidLog'
#    DEFAULT_REPORT_DIR = 'SandDroidReport'
#    DEFAULT_BAK_DIR = 'SandDroidBAK'
#    FAILED_BAK_DIR = 'SandDroidFailed'
#    DECOMPRESS_DIR = 'SandDroidDecompress'
#    KEYTOOL_PATH = '/home/santoku/jdk1.7.0_11/bin/keytool'
#    EMAIL_CONT = 'resources/emailHeader.txt'
#    
#    ICE_DIR = r'/home/santoku/IceAPKs'
#    ICE_JSON = r'ice.json'
#    
#    # Static information
#    STATIC_INFO = 'static'
#    PERMS_INFO = 'perms'
#    COMPONENTS_INFO = 'components'
#    SMALI_INFO = 'smali' # include sensitive apis, strings, ads module, urls
#    CLASSIFY_INFO = 'classify'
#    ANDROGUARD_INFO = 'androguard'
#    
#    # Dynamic information
#    DYNAMIC_INFO = 'dynamic'
#    
#    # Database information
#    SQL_SERVER = '127.0.0.1'
#    SQL_USER = 'root'
#    SQL_PWD = 'toor'
#    SQL_DB = 'sanddroid'
#    
#    # Risk Value Percentage
#    RISK_PERT = [0.2, 0.4, 0.4]
#    
#    LONG_PLUS_SIGN = 47 * '+'
#    SHORT_PLUS_SIGN = 4 * '+'
#    LONG_SPACE = 20 * ' '
#    LONG_EQUAL_SIGN = 47 * '='
#    
#    THREAD_JOIN_LONG_TIME = 60
#    THREAD_JOIN_SHORT_TIME = 10
#    THREAD_SLEEP_LONG_TIME =30
#    THREAD_SLEEP_SHORT_TIME = 10
#    APP_RUN_TIME = 5
#    
#
#from database.dbprocessor import DBProcessor
#
#dbProcessor = DBProcessor(SandDroidConst.SQL_SERVER, SandDroidConst.SQL_USER
#                                   ,SandDroidConst.SQL_DB, SandDroidConst.SQL_PWD)
#dbProcessor.connect()
#
#                
#fileMd5 = 'A478B7801DAE4779D73AA708511C26A5' 
#sqlStr = "select analyzed,email from filerecords where md5='%s'" % fileMd5
#queryRes = dbProcessor.query(sqlStr)
#
#if len(queryRes) != 0:
#    print queryRes
#    # check if analyzed
#    if queryRes[0][0]  != 0:
#       
#        sqlStr = "update filerecords set upload_time=now() where md5='%s'" % fileMd5
#       
#        
#        # check if need sending email
#        email = queryRes[0][1]
#        print email
#        if email != None and email != "":
#         
#            subject = 'SandDroid Report of %s' % fileMd5
#            url = 'http://sanddroid.xjtu.edu.cn/report_view?md5=%s' % fileMd5
##import os
##import traceback
##
##def sendEmail( mailTo, sub, url):
##        """
##        Send email
##        """
##        import smtplib
##        from email.mime.text import MIMEText
##        
##        mailHost = 'smtp.163.com'
##        mailUser = 'sanddroid'
##        mailPswd = 'droid@xjtu2013'
##        mailPostFix = '163.com'
##        
##        mailFrom = '%s<%s@%s>' % ('SandDroid', mailUser, mailPostFix)
##        try:
##            fobj = open('resources/emailHeader.txt')
##        except IOError:
##            pass
##        try:
##            header = fobj.read()
##        except IOError:
##            pass
##        finally:
##            fobj.close()
##            
##        
##        content = '%s%s%s%s%s %s%s %s' % (header, os.linesep, 
##                                'The File You Uploaded Has Been Analysed!', os.linesep,
##                                'Click:<a href="www.baidu.com">', url, '</href>', 'to view!')
##        msg = MIMEText(content)
##        msg['Subject'] = sub
##        msg['From'] = mailFrom
##        msg['To'] = mailTo
##        
##        try:
##            smtp = smtplib.SMTP()
##            smtp.connect(mailHost)
##            smtp.login(mailUser, mailPswd)
##            smtp.sendmail(mailFrom, mailTo, msg.as_string())
##            smtp.close()
##            
##        except:
##            exc = traceback.format_exc()
##            
# from database.dbprocessor import DBProcessor
# import os
# import shutil
# 
# SQL_SERVER = '127.0.0.1'
# SQL_USER = 'root'
# SQL_PWD = 'mindmac'
# SQL_DB = 'sanddroid'
# 
# dbProcessor = DBProcessor(SQL_SERVER, SQL_USER,SQL_DB, SQL_PWD)
# dbProcessor.connect()
# 
# sqlStr = "select md5 from filerecords where virusscanned=0"
# resets = dbProcessor.query(sqlStr)
# 
# for res in resets:
#     try:
#         md5 = res[0]
#         srcPath = os.path.join('/home/santoku/workspace/SandDroid/SandDroidBAK',md5+'.apk')
#         dstPath = os.path.join('/media/6831-E864/Samples', md5+'.apk')
#         shutil.copy(srcPath, dstPath)
#     except:
#         continue

# import sys
# import os
# import re  
# 
# osHomeDir = os.getenv('HOME')
# imageDir = os.path.join(osHomeDir, 'android', '.avd', 'a.img')
# print imageDir
# 
# from models import *
# 
# # configure database
# DATABASE_USER = 'root'
# DATABASE_PSWD = 'mindmac'
# DATABASE_URL = 'localhost'
# DATABASE_PORT = '3306'
# DATABASE_NAME = 'sanddroid'
# 
# dataModel = DataModel(DATABASE_USER, DATABASE_PSWD,
#                       DATABASE_URL, DATABASE_PORT,DATABASE_NAME)
# 
# session1 = dataModel.createSession(True)
# session2 = dataModel.createSession(True)
# num1 = session2.query(APK).count()
# print num1
# apk1 = APK(application_name="sanguo")
# session1.add(apk1)
# session1.commit()
# session2.rollback()
# num2 = session2.query(APK).count()
# print num2
# # import os
# # logging.basicConfig(filename = os.path.join(os.getcwd(), 'log.txt'), level = logging.WARN, filemode = 'w', format = '%(asctime)s - %(levelname)s: %(message)s')  
# # logging.debug('debug')
# # logging.info('info')    
# # logging.warning('warn')  
# # logging.error('error')  
# 
# #2009-07-13 21:42:15,592 - WARNING: warn  
# #2009-07-13 21:42:15,640 - ERROR: error  
# 
# engine = create_engine("mysql+pymysql://%s:%s@%s:%s/%s?charset=utf8" 
#                       % (DATABASE_USER, DATABASE_PSWD, DATABASE_URL,
#                          DATABASE_PORT, DATABASE_NAME), 
#                       echo=True)
# Base.metadata.create_all(engine)

import os
print os.path.dirname(__file__)
    
