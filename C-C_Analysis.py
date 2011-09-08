#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
# Offline Memory Forensics - https://github.com/npascan/OMF
# Project : C & C Extracter via PhyMemory
# Filename : fast_c_and_c.py
# Author : Tsung Pei Kan (PK)
# Co-Author : Jiang Xin-Zong (JaPang)
# Copyright (C) 2011 by Tsung Pei Kan
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
# ------------------------------------------------------------------------------

import re
import mmap
import os
import sys
import string
import optparse

def help():
	print
	print "¡° C & C Extracter - A memory forensics analysis platform. ¡°"
	print
	print "Usage¡G Process -f MemoryDumpImage [option] ClearFile"
	print
	print "Option¡@","Description"
	print "------¡@","-----------------"
	print "¡@-f¡@¡@","Memory Dump File"
	print "¡@-s¡@¡@","Build Clear List"
	print "¡@-l¡@¡@","Load Clear List"
	print
	print	"Samples Description¡@¡@¡@¡@¡@","Instruction"
	print "----------------------------¡@---------------------------------------------"
	print "First time(Build Clear List)¡@fast_c_and_c.py -f xxxx.vmem -s clearlist.txt"
	print "Next time(Load Clear List)¡@¡@fast_c_and_c.py -f xxxx.vmem -l clearlist.txt"
	print
	print "¡° Before build your clearlist.txt, please make sure your VM environment already contains enough of default strings.  ¡°"

def clearListChk(list_str):
     cleardata = ("www.rsa.com","www.openssl.org","www.kaspersky.com",".kaspersky-labs.com","www.cisco.com",".comodo.com",".zonelabs.com",".antivir-pe.de",".pro.antivir.de",".avgate.net",".mcafee.com","www.mcafeesecurity.com","liveupdate.symantecliveupdate.com",".mcafeeasap.com",".yimg.com","4.8.1.5","4.5.6.7","6.7.8.5","6.7.8.9","6.1.1.3","6.1.1.2","8.7.0.129","4.5.8.9","3.4.7.8","1.2.3.4","2.3.6.7","3.4.19.11","9.1.0.35","6.1.1.4","5.6.9.5","2.3.4.5","4.7.8.9","3.4.8.9","4.4.4.4","3.6.1.166","1.2.3.6","1.0.1.4","2.4.8.13","1.6.0.36","6.0.250.6","1.2.0.4","7.7.7.3","3.4.6.7","3.4.8.9","6.6.2.5","5.6.8.9","4.7.8.9","4.5.6.9","1.2.4.5","1.2.8.9","2.3.7.8","7.7.7.8","1.1.1.2","6.1.1.12","6.1.1.17","9.4.1.3","6.1.1.10","6.1.1.4","6.1.1.13","6.1.1.11","9.4.1.30","4.1.4.12","1.1.0.12","1.4.2.13","1.7.0.11","4.9.9.2","7.0.9.2","2.4.7.2","8.7.0.100","1.2.15.2","5.2.4.2","8.8.8.3","7.8.8.8","2.23.42.7","3.6.1.5","3.3.0.96","1.0.1.23","7.3.1.3","7.6.0.4","7.3.6.5","1.0.1.24","7.9.8.2","8.5.0.3","1.0.6.2","9.6.0.2","6.4.4.6","4.2.8.2","3.6.0.9","2.0.1.49","8.8.4.8","5.6.7.8","c:\\","/search?q={search","</favoriteicon>","/results.aspx?q={searchterms}",".aspx?query={searchte","</companyname><f",",fileversion=\"\"","\",filedescriptio","</filedescription","7.3.4.7","1.21.21.21","12.4.0.6","1.0.5.21","www.linotypelibrary.com","www.pdf-repair.com")
     list_str = string.lower(list_str)
     for pattern in cleardata:
       pattern = string.lower(pattern)
       if list_str.find(pattern) >= 0:
         return True
     return False

def clearEXEChk(list_str):
     cleardata = ("psxss.exe","WISPTIS.EXE","wuauclt.exe","tasklist.exe","IME\\TINTLGNT\\TINTSETP.EXEk")
     list_str = string.lower(list_str)
     for pattern in cleardata:
       pattern = "C:\\WINDOWS\\system32\\" + pattern
       pattern = string.lower(pattern)
       if list_str.find(pattern) >= 0:
         return True
     return False     

def clearDLLChk(list_str):
     cleardata = ("comctl32.dll","gdi32.dll","shlwapi.dll","user32.dll","ddraw.dll","ws2_32.dll","shimeng.dll","lpk.dll","ole32.dll","advapi32.dll","kernel32.dll","msacm32.dll","oleaut32.dll","imm32.dll","usp10.dll","userenv.dll","uxtheme.dll","ntdll.dll","mpr.dll","psapi.dll","winmm.dll","secur32.dll","clbcatq.dll","apphelp.dll","rpcrt4.dll","msvcr71.dll","MSRDO20.DLL","TPVMMon.dll","TPVMMonUI.dll","TPVMMonUIdeu.dll","TPVMMonUIjpn.dll","TPVMMondeu.dll","TPVMMonjpn.dll","TPVMW32.dll","FM20.DLL","FM20CHT.DLL","MSCTF.DLL","MSCTFP.DLL","MSIMTF.DLL","MSUTB.DLL","RDOCURS.DLL","DIMM.DLL","MSSTDFMT.DLL","SCP32.DLL","MSSTKPRP.DLL","MSPRPCHT.DLL","MSVCP60.DLL","MFC42CHT.DLL","VBAME.DLL","ESENT.dll","msnetobj.dll","dbghelp.dll","version.dll","msvcrt.dll","ws2help.dll","dciman32.dll","msacm32.dll","odbcjt32.dll","tprdpw32.dll","iedkcs32.dll","jsproxy.dll")
     list_str = string.lower(list_str)
     for pattern in cleardata:
       pattern = "C:\\WINDOWS\\system32\\" + pattern
       pattern = string.lower(pattern)
       if list_str.find(pattern) >= 0:
         return True
     return False     
     
def clearProcChk(list_str):
     pattern = r"C:\\Program\sFiles\\"
     list_str = string.lower(list_str)
     pattern = string.lower(pattern)
     if re.match(pattern,list_str):
        return True
     else:
        return False

def clearProcChk1(list_str):
     pattern = r"\Wc:\\"
     if re.match(pattern, list_str):
        return True
     else:
        return False

def clearProcChk2(list_str):
     pattern = r"\\{1,2}\?\?\\c:\\"
     if re.match(pattern, list_str):
        return True
     else:
        return False

def clearProcChk3(list_str):
     pattern = r"\b\S{1,2}c:\\"
     if re.match(pattern, list_str):
        return True
     else:
        return False

def clearProcChk4(list_str):
     pattern = r"c:\\windows\\system32\\\S{0,}\.dll\S{0,17}\.exe"
     if re.match(pattern, list_str):
        return True
     else:
        return False

def clearProcChk5(list_str):
     pattern = r"\S{1,2}@c:\\"
     if re.match(pattern, list_str):
        return True
     else:
        return False
                                     	
def ipFormatChk(ip_str):
     pattern = r"\b([1-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\b"
     if re.match(pattern, ip_str):
        return True
     else:
        return False
        
def ipInterChk1(ip_str):
     pattern = r"\b10\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\b"
     if re.match(pattern, ip_str):
        return True
     else:
        return False        

def ipInterChk2(ip_str):
     pattern = r"\b172\.(1[6-9]|2[0-9]|3[0-1])\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\b"
     if re.match(pattern, ip_str):
        return True
     else:
        return False 
        
def ipInterChk3(ip_str):
     pattern = r"\b192\.168\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\b"
     if re.match(pattern, ip_str):
        return True
     else:
        return False

def ipInterChk4(ip_str):
     pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.0\b"
     if re.match(pattern, ip_str):
        return True
     else:
        return False
        
def ipInterChk5(ip_str):
     pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.1\b"
     if re.match(pattern, ip_str):
        return True
     else:
        return False                

def ipInterChk6(ip_str):
     pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.255\b"
     if re.match(pattern, ip_str):
        return True
     else:
        return False
        
def ipInterChk7(ip_str):
     pattern = r"\b\d\.\d\.0.\d\b"
     if re.match(pattern, ip_str):
        return True
     else:
        return False
        
def ipInterChk8(ip_str):
     pattern = r"\b\d\.0\.\d.\d\b"
     if re.match(pattern, ip_str):
        return True
     else:
        return False                
        
def ipFormatURL(ip_str):
     pattern = r"\b([1-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\/\b"
     if re.match(pattern, ip_str):
        return True
     else:
        return False

def ipFormatURL1(ip_str):
     pattern = r"\b([1-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])):\d{2,4}\b"
     if re.match(pattern, ip_str):
        return True
     else:
        return False

def SuspiciousChk(list_str):
     pattern = "C:\\Documents and Settings\\"
     pattern = string.lower(pattern)
     list_str = string.lower(list_str)
     if list_str.find(pattern) >= 0:
       return True
     return False
     
def SuspiciousChk1(list_str):
     pattern = "C:\\DOCUME~1\\"
     pattern = string.lower(pattern)
     list_str = string.lower(list_str)
     if list_str.find(pattern) >= 0:
       return True
     return False                

def SuspiciousChk2(list_str):
     pattern = "C:\\Windows\\System32\\"
     pattern = string.lower(pattern)
     list_str = string.lower(list_str)
     if list_str.find(pattern) >= 0:
       return True
     return False           

def SvchostChk(list_str):
     pattern = "C:\\WINDOWS\\system32\\svchost.exe"
     pattern = string.lower(pattern)
     list_str = string.lower(list_str)
     if list_str.find(pattern) >= 0:
       return True
     return False        
                
def savelist(file,savelist):
 os.system("cls")
 print
 sys.stdout.write("Data Processing ..")
 num = 0
 chunksize = 1024
 with open('memdump2.txt', 'w') as target:
  with open(file, "rb") as chunkfile:
   while True:
    chunk = chunkfile.read(chunksize)
    if chunk:
      for m in re.finditer("([\x20-\x7e]{6,})", chunk):
        patterns = r'\S{0,20}\.\S{1,20}'
        match_split=re.compile(patterns)
        urlStr = str(m.group(1))
        if re.findall(match_split,urlStr):
          target.write(urlStr)
          target.write("\n")
        if (num % 25000) == 0:
          sys.stdout.write(".")
        num += 1
    else:
      break
    chunkfile.flush()
   target.flush()
 print " Done¡I¡I\n"
 print "================¡@Build Clear List¡iStart¡j¡@==================="
 print
 sys.stdout.write("Progress¡G")
 num = 0
 pattern = r':\/\/[-A-Za-z0-9]\S{0,20}\.\S{1,20}\.\S{1,20}' 
 f = open("memdump2.txt",'r')
 match_urls=re.compile(pattern)
 with open(savelist, 'w') as target:
  for line in f.readlines():
       line = "".join(line.split("\n"))
       line = line.strip()
       line = "".join(line.split(" "))
       ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)
       url = re.findall(match_urls, line) 
       if (num % 15000) == 0:
        sys.stdout.write("¢g")
       num += 1
       if len(url) > 0:
         urlStr = str(url[0])
         urlStr = string.lower(urlStr)
         if ipInterChk1(urlStr) or ipInterChk2(urlStr) or ipInterChk3(urlStr) or ipInterChk4(urlStr) or ipInterChk5(urlStr) or ipInterChk6(urlStr) or ipInterChk7(urlStr) or ipInterChk8(urlStr) or urlStr.find("microsoft.com") >=0 or urlStr.find("shell.windows.com") >= 0 or urlStr.find("download.windowsupdate.com") >= 0 or urlStr.find("vmware.com") >= 0 or urlStr.find("verisign.com") >= 0 or urlStr.find("localhost") >= 0 or urlStr.find("sysinternals.com") >= 0 or urlStr.find(".INTRA.NPA.GOV.TW") >= 0 or urlStr.find("msn.com") >= 0 or urlStr.find("google.com") >= 0 or urlStr.find("www.passport.com") >= 0 or urlStr.find("comodo.net") >= 0 or urlStr.find("comodoca.com") >= 0 or urlStr.find("partner.fedexkinkos.com") >= 0 or urlStr.find("hardware-update.com") >= 0 or urlStr.find("cyscape.com") >= 0 or urlStr.find("easy_guestbook") >= 0 or urlStr.find("cjbasp4.0") >= 0 or urlStr.find("windowsmedia.com") >= 0 or urlStr.find("w3.org") >= 0 or urlStr.find("bpsoft.com") >= 0 or urlStr.find("idapro.com") >= 0 or urlStr.find("upnp/eventing/") >= 0 or urlStr.find("monotype.com") >= 0 or urlStr.find("///") >= 0 or urlStr.find("chinadfcg.com") >= 0 or urlStr.find("ahteam.org") >= 0 or urlStr.find("winpcap.org") >= 0 or urlStr.find("apsvans.com") >= 0 or urlStr.find("nhandan.info") >= 0 or urlStr.find("sweetscape.com") >= 0 or urlStr.find("LinotypeLibrary.com") >= 0 or urlStr.find("ncst.ernet.in") >= 0 or urlStr.find("trio.com") >= 0 or urlStr.find("ncst.ernet.in") >= 0 or urlStr.find("adobe.com") >= 0 or urlStr.find("schemas.openxmlformats.org") >= 0 or urlStr.find("xmlsoap.org") >= 0 or urlStr.find("usertrust.com") >= 0 or urlStr.find("valicert.com") >= 0 or urlStr.find("trustcenter.de") >= 0 or urlStr.find("netlock.net") >= 0 or urlStr.find("sia.it") >= 0 or urlStr.find("certplus.com") >= 0 or urlStr.find("digsigtrust.com") >= 0 or urlStr.find("analysis.avira.com") >= 0 or urlStr.find("tiro.com") >= 0 or urlStr.find("entrust.net") >= 0 or urlStr.find("thawte.com") >= 0 or urlStr.find("macrovision.com") >= 0 or urlStr.find("acrobat.com") >= 0 or urlStr.find(".verisign") >= 0 or urlStr.find("yahoo.com") >= 0 or urlStr.find("acrobat.com") >= 0 or urlStr.find("macromedia.com") >= 0 or urlStr.find("purl.org") >= 0 or urlStr.find("aiim.org") >= 0 or urlStr.find("iptc.org") >= 0 or urlStr.find("sun.com") >= 0 or urlStr.find("iec.ch") >= 0 or urlStr.find("npes.org") >= 0 or urlStr.find("winimage.com") >= 0 or urlStr.find("eprint.fede") >= 0 or urlStr.find("xfa.org") >= 0 or urlStr.find("gwg.org") >= 0 or urlStr.find("/C:/") >= 0 or urlStr.find("xfa.com") >= 0 or urlStr.find("oasis-open.org") >= 0 or urlStr.find("python.org") >= 0 or urlStr.find("googlecode.com") >= 0 or urlStr.find("java.com") >= 0 or urlStr.find("freedesktop.org") >= 0 or urlStr.find("rsac.org") >= 0 or urlStr.find("tempuri.org") >= 0 or urlStr.find("wosign.com") >= 0 or urlStr.find("www.oberhumer.com") >= 0 or urlStr.find(".globalsign.net") >= 0 or urlStr.find("honeynet.org") >= 0 or urlStr.find("lists.gnupg.org") >= 0 or urlStr.find("www.namazu.org") >= 0 or urlStr.find("www.libpng.org") >= 0 or urlStr.find("hdf.ncsa.uiuc.edu") >= 0 or urlStr.find("www.inform-fiction.org") >= 0 or urlStr.find("www.djvuzone.org") >= 0 or urlStr.find("www.lua.org") >= 0 or urlStr.find("www.gingerall.org") >= 0 or urlStr.find("ns.adobe.") >= 0 or urlStr.find("com.adobe.acrobat") >= 0 or urlStr.find(".dll/") >= 0:
          continue
         else:
            patterns = r':\/\/'
            match_split = re.compile(patterns)
            if re.findall(match_split,urlStr):
              urlStr = str(urlStr.split(r'://')[1])
              patterns = r'"'
              match_split = re.compile(patterns)
              if re.findall(match_split,urlStr):
                continue
            else:
              urlStr = str(url[0])
            patterns = r'"'
            match_split=re.compile(patterns)
            if re.findall(match_split,urlStr) or ipInterChk1(urlStr) or ipInterChk2(urlStr) or ipInterChk3(urlStr) or ipInterChk4(urlStr) or ipInterChk5(urlStr) or ipInterChk6(urlStr) or ipInterChk7(urlStr) or ipInterChk8(urlStr):
              continue
            else:
              urlStr = urlStr.split(r';')[0]
              urlStr = urlStr.split(r'<')[0]
              urlStr = urlStr.split(r'>')[0]
              urlStr = urlStr.split(r')')[0]
              target.write(urlStr)
              target.write("\n")
       if len(ip) > 0 and ipFormatChk(ip[0]):
         if ipInterChk1(ip[0]) or ipInterChk2(ip[0]) or ipInterChk3(ip[0]) or ipInterChk4(ip[0]) or ipInterChk5(ip[0]) or ipInterChk6(ip[0]) or ipInterChk7(ip[0]) or ipInterChk8(ip[0]) or ip[0].find("127.0.0.1") >=0 or ip[0].find("1.1.1.1") >=0 or ip[0].find("9.3.3.177") >=0 or ip[0].find("2.5.") >=0 or ip[0].find("0.0.0.0") >=0 or ip[0].find("9.9.9.9") >=0 or ip[0].find("0.0") >=0 or ip[0].find("1.3.") >=0 or ip[0].find("5.5.") >=0 or ip[0].find("3.11.") >=0 or ip[0].find("255.255") >=0 or ip[0].find("5.1.1") >=0 or ip[0].find("5.2.2.1") >=0 or ip[0].find("6.1.4.1") >=0 or ip[0].find("6.1.5.5") >=0 or ip[0].find("49.1.7.6") >=0 or ip[0].find("9.16.2.2") >=0 or ip[0].find("193.128.177.124") >=0 or ip[0].find("5.2.2.3") >=0 or ip[0].find("7.7.7.7") >=0 or ip[0].find("1.4.5") >=0 or ip[0].find("169.254.") >=0 or ip[0].find("6.0.1.0") >=0 or ip[0].find("3.3.3.3") >=0 or ip[0].find("1.4.5.0") >=0 or ip[0].find("0.1.2.3") >=0 or ip[0].find("210.177.190.8") >=0 or ip[0].find("38.25.63.10") >=0 or ip[0].find("14.3.2.12") >=0 or ip[0].find("6.6.6.6") >=0 or ip[0].find("1.9.0") >=0 or ip[0].find("157.55.94.74") >=0 or ip[0].find("2.2.2.5") >=0 or ip[0].find("2.2.2.2") >=0 or ip[0].find("0.3.5.6") >=0 or ip[0].find("8.8.8.8") >=0 or ip[0].find("0.100.1.25") >=0 or ip[0].find("102.54.94.97") >=0:
          continue
         else:
            if ipFormatURL(line) or ipFormatURL1(line):
              patterns = r'"'
              match_split=re.compile(patterns)
              if clearListChk(line) or ipInterChk1(line) or ipInterChk2(line) or ipInterChk3(line) or ipInterChk4(line) or ipInterChk5(line) or ipInterChk6(line) or ipInterChk7(line) or ipInterChk8(line):
                continue
              elif re.findall(match_split, line):
                target.write(re.findall(match_split,line)[0])
                target.write("\n")
              else:
                target.write(line)
                target.write("\n")
            else:
              target.write(ip[0])
              target.write("\n")
  target.flush()
 f.close()
 num = 0
 with open("memdump2.txt",'r') as f:
   with open('ClearProc.txt', 'w') as dumpfl:
     for line in f.readlines():
       line = "".join(line.split("\n"))
       line = line.strip()
       if (num % 15000) == 0:
         sys.stdout.write("¢g")
       num += 1
       if SuspiciousChk(line) or SuspiciousChk1(line) or SuspiciousChk2(line):
         pattern1 = r'\.exe'
         match_proc1 = re.compile(pattern1)
         pattern = r'\.dll'
         match_proc = re.compile(pattern)
         if SvchostChk(line):
           continue
         else:
           if re.findall(match_proc1, line) or re.findall(match_proc, line):
             line = string.lower(line)
             dumpfl.write(line)
             dumpfl.write("\n")
     dumpfl.flush()
 print "\n"
 print "¡@¡°¡@Completion of %s and ClearProc.txt has been established.¡@¡°" % savelist
 print
 print "================¡@Build Clear List¡iComplete¡j¡@================"
 os.remove('memdump2.txt')
   
def main(file,loadlist):
 #os.system("cls")
 print
 sys.stdout.write("Data Processing ..")
 num = 0
 chunksize = 1024
 with open('memdump2.txt', 'w') as target:
  with open(file, "rb") as chunkfile:
   while True:
    chunk = chunkfile.read(chunksize)
    if chunk:
      for m in re.finditer("([\x20-\x7e]{4,})", chunk):
        patterns = r'\S{1,20}\.\S{1,20}'
        match_split=re.compile(patterns)
        urlStr = str(m.group(1))
        if re.findall(match_split,urlStr):
          target.write(urlStr)
          target.write("\n")
        if (num % 25000) == 0:
          sys.stdout.write(".")
        num += 1
    else:
      break
   chunkfile.flush()
  target.flush()
 print " Done¡I¡I\n"
 print "=================¡@C&C Server List¡iStart¡j¡@================="
 f = open("memdump2.txt",'r')
 f2 = open(loadlist,'r').read()
 flsize = int(os.path.getsize(file))
 pattern = r':\/\/[-A-Za-z0-9]\S{0,20}\.\S{1,20}\.\S{1,20}'
 match_urls = re.compile(pattern)
 pattern1 = r'\S{0,20}\.\S{1,20}\.\S{1,20}:80'
 match_urls1 = re.compile(pattern1)
 pattern2 = r'\S{0,20}\.\S{1,20}\.\S{1,20}:443'
 match_urls2 = re.compile(pattern2)
 with open('DumpList.txt', 'w') as dumpfl:
  for line in f.readlines():
       line = "".join(line.split("\n"))
       line = line.strip()
       ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)
       url = re.findall(match_urls, line) 
       if len(url) > 0:
         urlStr = str(url[0])
         urlStr = string.lower(urlStr)
         if clearListChk(urlStr) or ipInterChk1(urlStr) or ipInterChk2(urlStr) or ipInterChk3(urlStr) or ipInterChk4(urlStr) or ipInterChk5(urlStr) or ipInterChk6(urlStr) or ipInterChk7(urlStr) or ipInterChk8(urlStr) or urlStr.find("microsoft.com") >=0 or urlStr.find("shell.windows.com") >= 0 or urlStr.find("download.windowsupdate.com") >= 0 or urlStr.find("vmware.com") >= 0 or urlStr.find("verisign.com") >= 0 or urlStr.find("localhost") >= 0 or urlStr.find("sysinternals.com") >= 0 or urlStr.find(".INTRA.NPA.GOV.TW") >= 0 or urlStr.find("msn.com") >= 0 or urlStr.find("google.com") >= 0 or urlStr.find("www.passport.com") >= 0 or urlStr.find("comodo.net") >= 0 or urlStr.find("comodoca.com") >= 0 or urlStr.find("partner.fedexkinkos.com") >= 0 or urlStr.find("hardware-update.com") >= 0 or urlStr.find("cyscape.com") >= 0 or urlStr.find("easy_guestbook") >= 0 or urlStr.find("cjbasp4.0") >= 0 or urlStr.find("windowsmedia.com") >= 0 or urlStr.find("w3.org") >= 0 or urlStr.find("bpsoft.com") >= 0 or urlStr.find("idapro.com") >= 0 or urlStr.find("upnp/eventing/") >= 0 or urlStr.find("monotype.com") >= 0 or urlStr.find("///") >= 0 or urlStr.find("chinadfcg.com") >= 0 or urlStr.find("ahteam.org") >= 0 or urlStr.find("winpcap.org") >= 0 or urlStr.find("apsvans.com") >= 0 or urlStr.find("nhandan.info") >= 0 or urlStr.find("sweetscape.com") >= 0 or urlStr.find("LinotypeLibrary.com") >= 0 or urlStr.find("ncst.ernet.in") >= 0 or urlStr.find("trio.com") >= 0 or urlStr.find("ncst.ernet.in") >= 0 or urlStr.find("adobe.com") >= 0 or urlStr.find("schemas.openxmlformats.org") >= 0 or urlStr.find("xmlsoap.org") >= 0 or urlStr.find("usertrust.com") >= 0 or urlStr.find("valicert.com") >= 0 or urlStr.find("trustcenter.de") >= 0 or urlStr.find("netlock.net") >= 0 or urlStr.find("sia.it") >= 0 or urlStr.find("certplus.com") >= 0 or urlStr.find("digsigtrust.com") >= 0 or urlStr.find("analysis.avira.com") >= 0 or urlStr.find("tiro.com") >= 0 or urlStr.find("entrust.net") >= 0 or urlStr.find("thawte.com") >= 0 or urlStr.find("macrovision.com") >= 0 or urlStr.find("acrobat.com") >= 0 or urlStr.find(".verisign") >= 0 or urlStr.find("yahoo.com") >= 0 or urlStr.find("acrobat.com") >= 0 or urlStr.find("macromedia.com") >= 0 or urlStr.find("purl.org") >= 0 or urlStr.find("aiim.org") >= 0 or urlStr.find("iptc.org") >= 0 or urlStr.find("sun.com") >= 0 or urlStr.find("iec.ch") >= 0 or urlStr.find("npes.org") >= 0 or urlStr.find("winimage.com") >= 0 or urlStr.find("eprint.fede") >= 0 or urlStr.find("xfa.org") >= 0 or urlStr.find("gwg.org") >= 0 or urlStr.find("/C:/") >= 0 or urlStr.find("xfa.com") >= 0 or urlStr.find("oasis-open.org") >= 0 or urlStr.find("python.org") >= 0 or urlStr.find("googlecode.com") >= 0 or urlStr.find("java.com") >= 0 or urlStr.find("freedesktop.org") >= 0 or urlStr.find("rsac.org") >= 0 or urlStr.find("tempuri.org") >= 0 or urlStr.find("wosign.com") >= 0 or urlStr.find("www.oberhumer.com") >= 0 or urlStr.find(".globalsign.net") >= 0 or urlStr.find("honeynet.org") >= 0 or urlStr.find("lists.gnupg.org") >= 0 or urlStr.find("www.namazu.org") >= 0 or urlStr.find("www.libpng.org") >= 0 or urlStr.find("hdf.ncsa.uiuc.edu") >= 0 or urlStr.find("www.inform-fiction.org") >= 0 or urlStr.find("www.djvuzone.org") >= 0 or urlStr.find("www.lua.org") >= 0 or urlStr.find("www.gingerall.org") >= 0 or urlStr.find("ns.adobe.") >= 0 or urlStr.find("com.adobe.acrobat") >= 0 or urlStr.find(".dll/") >= 0:
          continue
         else:
          if f2.find(url[0]) < 0:
            patterns = r':\/\/'
            match_split = re.compile(patterns)
            if re.findall(match_split,urlStr):
              urlStr = str(urlStr.split(r'://')[1])
              patterns = r'"'
              match_split = re.compile(patterns)
              if re.findall(match_split,urlStr):
                continue 
            else:
              urlStr = str(url[0])
            patterns = r'"'
            match_split=re.compile(patterns)
            if re.findall(match_split,urlStr) or clearListChk(urlStr) or ipInterChk1(urlStr) or ipInterChk2(urlStr) or ipInterChk3(urlStr) or ipInterChk4(urlStr) or ipInterChk5(urlStr) or ipInterChk6(urlStr) or ipInterChk7(urlStr) or ipInterChk8(urlStr):
              continue
            else:
              urlStr = urlStr.split(r';')[0]
              urlStr = urlStr.split(r'<')[0]
              urlStr = urlStr.split(r'>')[0]
              urlStr = urlStr.split(r')')[0]
              if f2.find(urlStr) < 0:
                print urlStr
                if flsize >= 1073741824:
                  dumpfl.write(urlStr)
                  dumpfl.write("\n")
       url = re.findall(match_urls1, line) 
       if len(url) > 0:
         urlStr = str(url[0])
         urlStr = string.lower(urlStr)
         if clearListChk(urlStr) or ipInterChk1(urlStr) or ipInterChk2(urlStr) or ipInterChk3(urlStr) or ipInterChk4(urlStr) or ipInterChk5(urlStr) or ipInterChk6(urlStr) or ipInterChk7(urlStr) or ipInterChk8(urlStr) or urlStr.find("microsoft.com") >=0 or urlStr.find("shell.windows.com") >= 0 or urlStr.find("download.windowsupdate.com") >= 0 or urlStr.find("vmware.com") >= 0 or urlStr.find("verisign.com") >= 0 or urlStr.find("localhost") >= 0 or urlStr.find("sysinternals.com") >= 0 or urlStr.find(".INTRA.NPA.GOV.TW") >= 0 or urlStr.find("msn.com") >= 0 or urlStr.find("google.com") >= 0 or urlStr.find("www.passport.com") >= 0 or urlStr.find("comodo.net") >= 0 or urlStr.find("comodoca.com") >= 0 or urlStr.find("partner.fedexkinkos.com") >= 0 or urlStr.find("hardware-update.com") >= 0 or urlStr.find("cyscape.com") >= 0 or urlStr.find("easy_guestbook") >= 0 or urlStr.find("cjbasp4.0") >= 0 or urlStr.find("windowsmedia.com") >= 0 or urlStr.find("w3.org") >= 0 or urlStr.find("bpsoft.com") >= 0 or urlStr.find("idapro.com") >= 0 or urlStr.find("upnp/eventing/") >= 0 or urlStr.find("monotype.com") >= 0 or urlStr.find("///") >= 0 or urlStr.find("chinadfcg.com") >= 0 or urlStr.find("ahteam.org") >= 0 or urlStr.find("winpcap.org") >= 0 or urlStr.find("apsvans.com") >= 0 or urlStr.find("nhandan.info") >= 0 or urlStr.find("sweetscape.com") >= 0 or urlStr.find("LinotypeLibrary.com") >= 0 or urlStr.find("ncst.ernet.in") >= 0 or urlStr.find("trio.com") >= 0 or urlStr.find("ncst.ernet.in") >= 0 or urlStr.find("adobe.com") >= 0 or urlStr.find("schemas.openxmlformats.org") >= 0 or urlStr.find("xmlsoap.org") >= 0 or urlStr.find("usertrust.com") >= 0 or urlStr.find("valicert.com") >= 0 or urlStr.find("trustcenter.de") >= 0 or urlStr.find("netlock.net") >= 0 or urlStr.find("sia.it") >= 0 or urlStr.find("certplus.com") >= 0 or urlStr.find("digsigtrust.com") >= 0 or urlStr.find("analysis.avira.com") >= 0 or urlStr.find("tiro.com") >= 0 or urlStr.find("entrust.net") >= 0 or urlStr.find("thawte.com") >= 0 or urlStr.find("macrovision.com") >= 0 or urlStr.find("acrobat.com") >= 0 or urlStr.find(".verisign") >= 0 or urlStr.find("yahoo.com") >= 0 or urlStr.find("acrobat.com") >= 0 or urlStr.find("macromedia.com") >= 0 or urlStr.find("purl.org") >= 0 or urlStr.find("aiim.org") >= 0 or urlStr.find("iptc.org") >= 0 or urlStr.find("sun.com") >= 0 or urlStr.find("iec.ch") >= 0 or urlStr.find("npes.org") >= 0 or urlStr.find("winimage.com") >= 0 or urlStr.find("eprint.fede") >= 0 or urlStr.find("xfa.org") >= 0 or urlStr.find("gwg.org") >= 0 or urlStr.find("/C:/") >= 0 or urlStr.find("xfa.com") >= 0 or urlStr.find("oasis-open.org") >= 0 or urlStr.find("python.org") >= 0 or urlStr.find("googlecode.com") >= 0 or urlStr.find("java.com") >= 0 or urlStr.find("freedesktop.org") >= 0 or urlStr.find("rsac.org") >= 0 or urlStr.find("tempuri.org") >= 0 or urlStr.find("wosign.com") >= 0 or urlStr.find("www.oberhumer.com") >= 0 or urlStr.find(".globalsign.net") >= 0 or urlStr.find("honeynet.org") >= 0 or urlStr.find("lists.gnupg.org") >= 0 or urlStr.find("www.namazu.org") >= 0 or urlStr.find("www.libpng.org") >= 0 or urlStr.find("hdf.ncsa.uiuc.edu") >= 0 or urlStr.find("www.inform-fiction.org") >= 0 or urlStr.find("www.djvuzone.org") >= 0 or urlStr.find("www.lua.org") >= 0 or urlStr.find("www.gingerall.org") >= 0 or urlStr.find("ns.adobe.") >= 0 or urlStr.find("com.adobe.acrobat") >= 0 or urlStr.find(".dll/") >= 0:
          continue
         else:
          if f2.find(url[0]) < 0:
            patterns = r':\/\/'
            match_split = re.compile(patterns)
            if re.findall(match_split,urlStr):
              urlStr = str(urlStr.split(r'://')[1])
              patterns = r'"'
              match_split = re.compile(patterns)
              if re.findall(match_split,urlStr):
                continue 
            else:
              urlStr = str(url[0])
            patterns = r'"'
            match_split=re.compile(patterns)
            if re.findall(match_split,urlStr) or clearListChk(urlStr) or ipInterChk1(urlStr) or ipInterChk2(urlStr) or ipInterChk3(urlStr) or ipInterChk4(urlStr) or ipInterChk5(urlStr) or ipInterChk6(urlStr) or ipInterChk7(urlStr) or ipInterChk8(urlStr):
              continue
            else:
              urlStr = urlStr.split(r';')[0]
              urlStr = urlStr.split(r'<')[0]
              urlStr = urlStr.split(r'>')[0]
              urlStr = urlStr.split(r')')[0]
              if f2.find(urlStr) < 0:
                print urlStr
                if flsize >= 1073741824:
                  dumpfl.write(urlStr)
                  dumpfl.write("\n")
       url = re.findall(match_urls2, line) 
       if len(url) > 0:
         urlStr = str(url[0])
         urlStr = string.lower(urlStr)
         if clearListChk(urlStr) or ipInterChk1(urlStr) or ipInterChk2(urlStr) or ipInterChk3(urlStr) or ipInterChk4(urlStr) or ipInterChk5(urlStr) or ipInterChk6(urlStr) or ipInterChk7(urlStr) or ipInterChk8(urlStr) or urlStr.find("microsoft.com") >=0 or urlStr.find("shell.windows.com") >= 0 or urlStr.find("download.windowsupdate.com") >= 0 or urlStr.find("vmware.com") >= 0 or urlStr.find("verisign.com") >= 0 or urlStr.find("localhost") >= 0 or urlStr.find("sysinternals.com") >= 0 or urlStr.find(".INTRA.NPA.GOV.TW") >= 0 or urlStr.find("msn.com") >= 0 or urlStr.find("google.com") >= 0 or urlStr.find("www.passport.com") >= 0 or urlStr.find("comodo.net") >= 0 or urlStr.find("comodoca.com") >= 0 or urlStr.find("partner.fedexkinkos.com") >= 0 or urlStr.find("hardware-update.com") >= 0 or urlStr.find("cyscape.com") >= 0 or urlStr.find("easy_guestbook") >= 0 or urlStr.find("cjbasp4.0") >= 0 or urlStr.find("windowsmedia.com") >= 0 or urlStr.find("w3.org") >= 0 or urlStr.find("bpsoft.com") >= 0 or urlStr.find("idapro.com") >= 0 or urlStr.find("upnp/eventing/") >= 0 or urlStr.find("monotype.com") >= 0 or urlStr.find("///") >= 0 or urlStr.find("chinadfcg.com") >= 0 or urlStr.find("ahteam.org") >= 0 or urlStr.find("winpcap.org") >= 0 or urlStr.find("apsvans.com") >= 0 or urlStr.find("nhandan.info") >= 0 or urlStr.find("sweetscape.com") >= 0 or urlStr.find("LinotypeLibrary.com") >= 0 or urlStr.find("ncst.ernet.in") >= 0 or urlStr.find("trio.com") >= 0 or urlStr.find("ncst.ernet.in") >= 0 or urlStr.find("adobe.com") >= 0 or urlStr.find("schemas.openxmlformats.org") >= 0 or urlStr.find("xmlsoap.org") >= 0 or urlStr.find("usertrust.com") >= 0 or urlStr.find("valicert.com") >= 0 or urlStr.find("trustcenter.de") >= 0 or urlStr.find("netlock.net") >= 0 or urlStr.find("sia.it") >= 0 or urlStr.find("certplus.com") >= 0 or urlStr.find("digsigtrust.com") >= 0 or urlStr.find("analysis.avira.com") >= 0 or urlStr.find("tiro.com") >= 0 or urlStr.find("entrust.net") >= 0 or urlStr.find("thawte.com") >= 0 or urlStr.find("macrovision.com") >= 0 or urlStr.find("acrobat.com") >= 0 or urlStr.find(".verisign") >= 0 or urlStr.find("yahoo.com") >= 0 or urlStr.find("acrobat.com") >= 0 or urlStr.find("macromedia.com") >= 0 or urlStr.find("purl.org") >= 0 or urlStr.find("aiim.org") >= 0 or urlStr.find("iptc.org") >= 0 or urlStr.find("sun.com") >= 0 or urlStr.find("iec.ch") >= 0 or urlStr.find("npes.org") >= 0 or urlStr.find("winimage.com") >= 0 or urlStr.find("eprint.fede") >= 0 or urlStr.find("xfa.org") >= 0 or urlStr.find("gwg.org") >= 0 or urlStr.find("/C:/") >= 0 or urlStr.find("xfa.com") >= 0 or urlStr.find("oasis-open.org") >= 0 or urlStr.find("python.org") >= 0 or urlStr.find("googlecode.com") >= 0 or urlStr.find("java.com") >= 0 or urlStr.find("freedesktop.org") >= 0 or urlStr.find("rsac.org") >= 0 or urlStr.find("tempuri.org") >= 0 or urlStr.find("wosign.com") >= 0 or urlStr.find("www.oberhumer.com") >= 0 or urlStr.find(".globalsign.net") >= 0 or urlStr.find("honeynet.org") >= 0 or urlStr.find("lists.gnupg.org") >= 0 or urlStr.find("www.namazu.org") >= 0 or urlStr.find("www.libpng.org") >= 0 or urlStr.find("hdf.ncsa.uiuc.edu") >= 0 or urlStr.find("www.inform-fiction.org") >= 0 or urlStr.find("www.djvuzone.org") >= 0 or urlStr.find("www.lua.org") >= 0 or urlStr.find("www.gingerall.org") >= 0 or urlStr.find("ns.adobe.") >= 0 or urlStr.find("com.adobe.acrobat") >= 0 or urlStr.find(".dll/") >= 0:
          continue
         else:
          if f2.find(url[0]) < 0:
            patterns = r':\/\/'
            match_split = re.compile(patterns)
            if re.findall(match_split,urlStr):
              urlStr = str(urlStr.split(r'://')[1])
              patterns = r'"'
              match_split = re.compile(patterns)
              if re.findall(match_split,urlStr):
                continue 
            else:
              urlStr = str(url[0])
            patterns = r'"'
            match_split=re.compile(patterns)
            if re.findall(match_split,urlStr) or clearListChk(urlStr) or ipInterChk1(urlStr) or ipInterChk2(urlStr) or ipInterChk3(urlStr) or ipInterChk4(urlStr) or ipInterChk5(urlStr) or ipInterChk6(urlStr) or ipInterChk7(urlStr) or ipInterChk8(urlStr):
              continue
            else:
              urlStr = urlStr.split(r';')[0]
              urlStr = urlStr.split(r'<')[0]
              urlStr = urlStr.split(r'>')[0]
              urlStr = urlStr.split(r')')[0]
              if f2.find(urlStr) < 0:
                print urlStr
                if flsize >= 1073741824:
                  dumpfl.write(urlStr)
                  dumpfl.write("\n")
       if len(line) > 5:
         urlStr = string.lower(line)
         patterns = r'^\S{1,}\.\S{1,}\.(org|net|com|gov|cn|hk|at|ru|de|eu|tw)$'
         match_split = re.compile(patterns)
         if re.findall(match_split,urlStr):
           if not (clearListChk(urlStr) or (urlStr.find(".microsoft.com") >=0) or (urlStr.find(".google.com") >=0) or (urlStr.find(".msn.com") >=0) or (urlStr.find(".msdn.com") >=0) or (urlStr.find(".adobe.com") >=0) or (urlStr.find("www.macromedia.com") >=0) or (urlStr.find("www.msnusers.com") >=0) or (urlStr.find("tw.yahoo.com") >=0) or (urlStr.find("@") >=0)):
             patterns = r';'
             match_split = re.compile(patterns)
             if not re.findall(match_split,urlStr):
               print urlStr
       if len(ip) > 0 and ipFormatChk(ip[0]):
         if clearListChk(ip[0]) or ipInterChk1(ip[0]) or ipInterChk2(ip[0]) or ipInterChk3(ip[0]) or ipInterChk4(ip[0]) or ipInterChk5(ip[0]) or ipInterChk6(ip[0]) or ipInterChk7(ip[0]) or ipInterChk8(ip[0]) or ip[0].find("127.0.0.1") >=0 or ip[0].find("1.1.1.1") >=0 or ip[0].find("9.3.3.177") >=0 or ip[0].find("2.5.") >=0 or ip[0].find("0.0.0.0") >=0 or ip[0].find("9.9.9.9") >=0 or ip[0].find("0.0") >=0 or ip[0].find("1.3.") >=0 or ip[0].find("5.5.") >=0 or ip[0].find("3.11.") >=0 or ip[0].find("255.255") >=0 or ip[0].find("5.1.1") >=0 or ip[0].find("5.2.2.1") >=0 or ip[0].find("6.1.4.1") >=0 or ip[0].find("6.1.5.5") >=0 or ip[0].find("49.1.7.6") >=0 or ip[0].find("9.16.2.2") >=0 or ip[0].find("193.128.177.124") >=0 or ip[0].find("5.2.2.3") >=0 or ip[0].find("7.7.7.7") >=0 or ip[0].find("1.4.5") >=0 or ip[0].find("169.254.") >=0 or ip[0].find("6.0.1.0") >=0 or ip[0].find("3.3.3.3") >=0 or ip[0].find("1.4.5.0") >=0 or ip[0].find("0.1.2.3") >=0 or ip[0].find("210.177.190.8") >=0 or ip[0].find("38.25.63.10") >=0 or ip[0].find("14.3.2.12") >=0 or ip[0].find("6.6.6.6") >=0 or ip[0].find("1.9.0") >=0 or ip[0].find("157.55.94.74") >=0 or ip[0].find("2.2.2.5") >=0 or ip[0].find("2.2.2.2") >=0 or ip[0].find("0.3.5.6") >=0 or ip[0].find("8.8.8.8") >=0 or ip[0].find("0.100.1.25") >=0 or ip[0].find("102.54.94.97") >=0:
          continue
         else:
          if f2.find(ip[0]) < 0:
            if ipFormatURL(line) or ipFormatURL1(line):
              patterns = r'"'
              match_split=re.compile(patterns)
              if clearListChk(line) or ipInterChk1(line) or ipInterChk2(line) or ipInterChk3(line) or ipInterChk4(line) or ipInterChk5(line) or ipInterChk6(line) or ipInterChk7(line) or ipInterChk8(line):
                continue
              elif re.findall(match_split, line):
                print re.findall(match_split,line)[0]
                if flsize >= 1073741824:
                  dumpfl.write(re.findall(match_split,line)[0])
                  dumpfl.write("\n")
              else:
                print line
                if flsize >= 1073741824:
                  dumpfl.write(line)
                  dumpfl.write("\n")
            else:
              print ip[0]
              if flsize >= 1073741824:
                dumpfl.write(ip[0])
                dumpfl.write("\n")
  dumpfl.flush()
 f.close()
 print "=================¡@C&C Server List¡iEnd¡j¡@==================="
 print
 print "¡°==============¡@Suspicious File ¡iStart¡j¡@===============¡°"
 Procf = open("ClearProc.txt",'r').read()
 with open("memdump2.txt",'r') as f:
   with open('ProcList.txt', 'w') as dumpfl:
     for line in f.readlines():
       line = "".join(line.split("\n"))
       line = line.strip()
       line1 = string.lower(line)
       pattern1 = r'\.exe'
       match_proc1 = re.compile(pattern1)
       if re.findall(match_proc1, line1) and (SuspiciousChk(line1) or SuspiciousChk1(line1) or SuspiciousChk2(line1)):
         pattern = r'c:\\program files\\'
         match_proc = re.compile(pattern)
         if re.findall(match_proc, line1):
           continue
         procEXE = str(line1.split(".exe")[0]) + ".exe"
         line2 = string.lower(procEXE)
         if Procf.find(line) >= 0 or Procf.find(line1) >= 0 or Procf.find(line2) >= 0 or clearProcChk1(line2) or clearProcChk2(line2) or clearProcChk3(line2) or clearProcChk4(line2) or clearProcChk5(line2):
           continue
         else:
           pattern2 = r'svchost\.exe'
           match_proc2 = re.compile(pattern2)
           pattern3 = r'regsvr32\.exe'
           match_proc3 = re.compile(pattern3)
           pattern4 = r'taskmgr\.exe'
           match_proc4 = re.compile(pattern4)
           pattern5 = r'wmiprvse\.exe'
           match_proc5 = re.compile(pattern5)
           pattern6 = r'winlogon\.exe'
           match_proc6 = re.compile(pattern6)
           pattern7 = r'smss\.exe'
           match_proc7 = re.compile(pattern7)
           pattern8 = r'conime\.exe'
           match_proc8 = re.compile(pattern8)
           pattern9 = r'ctfmon\.exe'
           match_proc9 = re.compile(pattern9)
           pattern10 = r'\\winhlp32\.exe\s'
           match_proc10 = re.compile(pattern10)
           if re.findall(match_proc2, line2):
             if len(line2) != 31:
               pattern2 = r'C:\\WINDOWS\\System32\\svchost\.exe\s\-k\s'
               match_proc2 = re.compile(pattern2)
               if not re.findall(match_proc2, line1):
                 dumpfl.write(line)
                 dumpfl.write("\n")
                 print line
           elif re.findall(match_proc3, line2):
             if len(line2) != 32:
               dumpfl.write(line)
               dumpfl.write("\n")
               print line
           elif re.findall(match_proc4, line2):
             if len(line2) != 31:
               dumpfl.write(line)
               dumpfl.write("\n")
               print line
           elif re.findall(match_proc5, line2):
             if len(line2) != 37:
               dumpfl.write(line)
               dumpfl.write("\n")
               print line
           elif re.findall(match_proc6, line2):
             if len(line2) != 32:
               dumpfl.write(line)
               dumpfl.write("\n")
               print line
           elif re.findall(match_proc7, line2):
             if len(line2) != 28:
               dumpfl.write(line)
               dumpfl.write("\n")
               print line
           elif re.findall(match_proc8, line2):
             if len(line2) != 30:
               dumpfl.write(line)
               dumpfl.write("\n")
               print line
           elif re.findall(match_proc9, line2):
             if len(line2) != 34:
               dumpfl.write(line)
               dumpfl.write("\n")
               print line
           else:
             if not (re.findall(match_proc10, line) or clearEXEChk(line)):
               print line
       else:
         pattern2 = r'svchost\.exe\s'
         match_proc2 = re.compile(pattern2)
         pattern3 = r'\\system32\\svchost\.exe\s\-k'
         match_proc3 = re.compile(pattern3)
         if re.findall(match_proc2, line):
           if not re.findall(match_proc3, line):
             dumpfl.write(line)
             dumpfl.write("\n")
             print line
       pattern2 = r'\.dll\b'
       match_proc2 = re.compile(pattern2)
       if re.findall(match_proc2, line1) and (SuspiciousChk(line1) or SuspiciousChk1(line1) or SuspiciousChk2(line1)):
         if re.findall(match_proc1, line1):
           continue
         pattern = r'c:\\program files\\'
         match_proc = re.compile(pattern)
         if re.findall(match_proc2, line1):
           procDLL = str(line1.split(".dll")[0]) + ".dll"
           line2 = string.lower(procDLL)
           if Procf.find(line) >= 0 or Procf.find(line1) >= 0 or Procf.find(line2) >= 0 or clearProcChk1(line2) or clearProcChk2(line2) or clearProcChk3(line2) or clearProcChk4(line2) or clearProcChk5(line2):
             continue
           else:
             pattern3 = r'\.dll\[MofResourceName\]'
             match_proc3 = re.compile(pattern3)
             if not (re.findall(match_proc3, line) or clearDLLChk(line)):
               print line
     dumpfl.flush()
 print "¡°==============¡@Suspicious File ¡iEnd¡j¡@=================¡°"
 os.remove('memdump2.txt')
 if flsize >= 1073741824:
  print
  print "¡@¡°¡@The result of C&C list has been saved in DumpList.txt.¡@¡°"
 else:
  os.remove('DumpList.txt')
  os.remove('ProcList.txt')

if __name__ == "__main__":
    if sys.version_info < (2, 6, 0) or sys.version_info > (3, 0, 0):
      sys.stderr.write("C & C Extracter via PhyMemory requires python version 2.6 or 2.7, please upgrade your python installation.")
      os.system("pause")
      sys.exit(1)
    parser = optparse.OptionParser()
    parser.add_option("-f", "--file", action = "store", type = "string", dest = "configFile")
    parser.add_option("-l", "--list", action = "store", type = "string", dest = "LoadList")
    parser.add_option("-s", "--slist", action = "store", type = "string", dest = "sLoadList")
    options, args = parser.parse_args()
    try:
      if options.sLoadList and options.configFile:
        if not os.path.isfile(options.configFile):
          print
          print "Failed to open this Memory Dump File¡I¡I" 
        else:
          savelist(options.configFile,options.sLoadList)
      elif options.LoadList and options.configFile:
        if not os.path.isfile(options.LoadList):
          help()
          print
          print "Please Build Clear List First¡I¡I"
        elif not os.path.isfile(options.configFile):
          print
          print "Failed to open this Memory Dump File¡I¡I" 
        else:
          main(options.configFile,options.LoadList)
      elif options.configFile:
        if not os.path.isfile(options.configFile):
          print
          print "Failed to open this Memory Dump File¡I¡I" 
        else:
          dfclearlist = "clearlist2.txt"
          cleardata = ("127.0.0.1","1.1.1.1","9.3.3.177","2.5.","0.0.0.0","9.9.9.9","0.0","1.3.","5.5.","3.11.","255.255","5.1.1","5.2.2.1","6.1.4.1","6.1.5.5","49.1.7.6","9.16.2.2","193.128.177.124","5.2.2.3","7.7.7.7","1.4.5","169.254.","6.0.1.0","3.3.3.3","1.4.5.0","0.1.2.3","210.177.190.8","38.25.63.10","14.3.2.12","6.6.6.6","1.9.0","157.55.94.74","2.2.2.5","2.2.2.2","0.3.5.6","8.8.8.8","0.100.1.25","102.54.94.97","download.windowsupdate.com","microsoft.com","shell.windows.com","vmware.com","verisign.com","localhost","sysinternals.com","msn.com","google.com","www.passport.com","comodo.net","comodoca.com","partner.fedexkinkos.com","hardware-update.com","cyscape.com","easy_guestbook","cjbasp4.0","windowsmedia.com","w3.org","bpsoft.com","idapro.com","upnp/eventing/","monotype.com","///","chinadfcg.com","ahteam.org","winpcap.org","apsvans.com","nhandan.info","sweetscape.com","LinotypeLibrary.com","ncst.ernet.in","trio.com","ncst.ernet.in","adobe.com","schemas.openxmlformats.org","xmlsoap.org","usertrust.com","valicert.com","trustcenter.de","netlock.net","sia.it","certplus.com","digsigtrust.com","tiro.com","entrust.net","thawte.com","macrovision.com","acrobat.com",".verisign","yahoo.com","acrobat.com","macromedia.com","purl.org","aiim.org","iptc.org","sun.com","iec.ch","npes.org","winimage.com","eprint.fede","xfa.org","gwg.org","/C:/","xfa.com","oasis-open.org","python.org","googlecode.com","java.com","freedesktop.org","rsac.org","tempuri.org","wosign.com","www.oberhumer.com",".globalsign.net","honeynet.org","lists.gnupg.org","www.namazu.org","www.libpng.org","hdf.ncsa.uiuc.edu","www.inform-fiction.org","www.djvuzone.org","www.lua.org","www.gingerall.org","analysis.avira.com","ns.adobe.","com.adobe.acrobat",".dll/","help/?id=Microsoft.Windows.Resources.ShellExecuteTopicIco")
          with open(dfclearlist, 'w') as target:
            for elem in cleardata:
              target.write(elem)
              target.write("\n")
          cleardata = ("C:\WINDOWS\system32\defrag.exe","C:\WINDOWS\system32\DfrgNtfs.exe","C:\WINDOWS\system32\psxss.exe","C:\WINDOWS\system32\WISPTIS.EXE","C:\WINDOWS\system32\IME\TINTLGNT\TINTSETP.EXEk")
          with open('ClearProc.txt', 'w') as target:
            for elem in cleardata:
              target.write(elem)
              target.write("\n")
          main(options.configFile,dfclearlist)
          if os.path.isfile(dfclearlist):
            os.remove(dfclearlist)
          if os.path.isfile("ClearProc.txt"):
            os.remove("ClearProc.txt")
      else:
        os.system("cls")
        help()
    except KeyboardInterrupt:
        if os.path.isfile("memdump2.txt"):
          os.remove("memdump2.txt")
        if os.path.isfile("DumpList.txt"):
          os.remove("DumpList.txt")
        if os.path.isfile("clearlist2.txt"):
          os.remove("clearlist2.txt")
        print "Interrupted"
        