#!/usr/bin/env python
# -*- coding: utf-8 -*-

################################################################################
#
# Copyright (c) 2011-2012, Hu Wenjun (mindmac/hu@gmail/com)
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

ADMODULE = {  'com/google/ads':['AdMob','http://www.google.com/ads/admob/'],
              'com/baidu':['Baidu','http://munion.baidu.com/'],
              'net/youmi/android':['Youmi','http://www.youmi.net/'],
              'com/tencent/mobwin':['MobWin','http://mobwin.app.qq.com'],
              'com/wooboo':['Wooboo','http://www.wooboo.com.cn/'],
              'cn/casee':['Casee','http://www.casee.cn/mm/Index.ad'],
              'com/wiyun':['Wiyun','http://www.wiyun.com/'],
              'com/adchina':['AdChina','http://mobile.adchina.com/AboutUs/index.aspx'],
              'com/adwo/adsdk':['AdWo','http://www.adwo.com/'],
              'com/wq':['Wq','http://www.wqmobile.com/'],
              'cn/appmedia.ad':['AppMedia','http://www.appmedia.cn/top.action'],
              'com/ignitevision/andoroid':['Tinmoo','http://www.tinmoo.com/mobile/index.do'],
              'com/l/adlib_android':['LSense','http://www.lsense.cn/'],
              'com/winad/android':['Winad','http://www.winads.cn/'],
              'com/izp':['Izp','http://www.izptec.com/cn/'],
              'com/mobisage':['Mobisage','http://mobisage.ad-sage.com/'],
              'com/umengAd':['Umeng','http://ads.umeng.com/'],
              'com/fractalist':['Fractalist','http://www.admarket.mobi/'],
              'com/lmmob':['Lmmob','http://www.lmmob.com/'],
              'com/suizong/mobplate':['SuiZong','http://mobile.suizong.com/szmobile/szmWelcomeMgtMgr.action'],
              'cn/aduu/adsdk':['Aduu','http://www.aduu.cn/'],
              'com/millennialmedia/android':['MillennialMedia','http://www.millennialmedia.com/'],
              'com/greystripe/android':['Greystripe','http://www.greystripe.com/'],
              'com/inmobi/androidsdk':['InMobi','http://www.inmobi.com/'],
              'com/mdotm/android':['MdotM','http://mdotm.com/'],
              'com/zestadz/android':['ZestADZ','http://www.komlimobile.com/'],
              'com/smaato/SOMA':['Smaato','http://www.smaato.com/'],
              'com/waps': ['Waps','http://www.waps.cn'],
              'cn/waps': ['Waps','http://www.waps.cn'],
              'com/emar/escore': ['Yijifen','http://www.yijifen.com'],
              'com/juzi/main': ['Juzi','http://www.juzi.cn'],
              'com/kyview': ['Adview','http://www.adview.cn'],
              'com/energysource': ['Adtouch','http://www.adtouchnetwork.com/'],
              'com/mt/airad': ['AirAD ad','http://www.airad.com/'],
              'com/vpon/adon': ['Vpon','http://www.vpon.com/zh-cn/'],
              'cn/domob/android':['Domob','http://www.domob.cn'],
              'com/guohead/sdk':['GuoHead','http://www.guohead.com'],
          };