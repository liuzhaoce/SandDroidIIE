#!/usr/bin/env python
# -*- coding: utf-8 -*-

################################################################################
#
# Copyright (c) 2011-2012, Hu Wenjun (mindmac.hu@gmail.com)
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

SENSITIVESTR_DESC = { 
                        "/system/bin/sh": "Execute Shell",
                        "/proc/mounts": "Mount File System",
                        "/system/bin/cp": "Copy File",
                        "/root/su": "Change User to Root",
                        "/system/bin/rm": "Delete File",
                        "chmod": "Change File Permission",
                        "getRuntime": "Get Command Environment",
                        "mount -o remount" : "Remount File System",
                     }