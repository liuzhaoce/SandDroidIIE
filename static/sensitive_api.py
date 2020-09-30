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

SENSITIVEAPI_DESC = { 
                        "android/app/IActivityManager/$Stub/$Proxy;->shutdown": "Shutdown Device",
                        "android/app/ActivityManager;->killBackgroundProcesses": "Interrupt Process",
                        "android/app/ActivityManagerNative;->killBackgroundProcesses": "Interrupt Process",
                        "android/app/ActivityManagerNative;->restartPackage": "Interrupt Process",
                        "android/bluetooth/BluetoothAdapter;->enable": "Start Bluetooth",
                        "android/bluetooth/BluetoothSocket;->connect": "Connect Bluetooth",
                        "android/bluetoothIBluetoothPbap/$Stub/$Proxy;->connect": "Connect Bluetooth",
                        "android/content/ContentResolver;->query": "Query Database of Contacts,SMS,etc",
                        "android/content/ContentResolver;->dump": "Dump Database of Contacts,SMS,etc",
                        "android/content/pm/PackageManager;->installPackage": "Install APK File",
                        "android/hardware/Camera;->open": "Open Camera",
                        "android/media/MediaRecorder;->setAudioSource": "Record Voice",
                        "android/media/MediaRecorder;->setVideoSource": "Record Video",
                        "android/location/LocationManager;->setLastKnownLocation": "Get Location",
                        "Downloads/$ByUri;->startDownloadByUri": "Download File",
                        "Downloads/$DownloadBase;->startDownloadByUri": "Download File",
                        "android/os/PowerManager;->reboot": "Reboot Device",
                        "android/telephony/TelephonyManager;->getDeviceId": "Get Device IMEI and CellPhone Number,etc",
                        "android/telephony/TelephonyManager;->getSimSerialNumber": "Get SIM Serial Number",
                        "android/telephony/$Mms->query": "Read SMS",
                        "android/telephony/TelephonyManager;->getLine1Number": "Get CellPhone Number",
                        "android/speech/SpeechRecognizer;->startListening": "Open Microphone",
                        "android/net/wifi/WifiManager;->setWifiEnabled": "Start WIFI",
                        "android/telephony/gsm/SmsManager;->getAllMessagesFromSim": "Get All Messages From SIM",
                        "android/telephony/gsm/SmsManager;->sendDataMessage": "Send Binary Message",
                        "android/telephony/gsm/SmsManager;->sendMultipartTextMessage": "Send Multimedia Message",
                        "android/telephony/gsm/SmsManager;->sendTextMessage": "Send Text Message",
                        "android/telephony/SmsManager;->getAllMessagesFromSim": "Get All Messages From SIM",
                        "android/telephony/SmsManager;->sendDataMessage": "Send Binary Message",
                        "android/telephony/SmsManager;->sendMultipartTextMessage": "Send Multimedia Message",
                        "android/telephony/SmsManager;->sendTextMessage": "Send Text Message",
                        "http/multipart/FilePart;->sendData": "Send HTTP Request",
                        "http/multipart/Part;->send": "Send HTTP Request",
                        "http/multipart/Part;->sendParts": "Send HTTP Request",
                        "http/multipart/StringPart;->sendData": "Send HTTP Request",
                        "internal/telephony/ISms/$Stub/$Proxy;->sendData": "Send SMS",
                        "internal/telephony/ISms/$Stub/$Proxy;->sendMultipartText": "Send Multipart Text Message",
                        "internal/telephony/ISms/$Stub/$Proxy;->sendText": "Send Text Message",
                        "internal/telephony/ITelephony/$Stub/$Proxy;->call": "Call Phone",
                        "java/lang/Runtime;->exec": "Execute Command",
                        "java/lang/System;->loadLibrary": 'Dynamic load library',
                        "dalvick/system/DexClassLoader;-><init>": 'Dynamic load class',
                        "java/net/HttpURLConnection;->connect": "HTTP Connect",
                        "java/net/URL;->getContent": "Get Web Content",
                        "java/net/URL;->openConnection": "Open URL Connection",
                        "java/net/URLConnection;->connect": "URL Connect",
                        "DefaultHttpClient;->execute": "Send HTTP Request",
                        "HttpClient;->execute": "Request Remote Server",
                        "android/app/NotificationManager;->notify": "Notification",
                        "ContentResolver;->delete": "Delete SMS,Contacts,etc",
                    }