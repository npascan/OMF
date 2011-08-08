#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
# Project  : C & C Extracter via PhyMemory
# Filename : fast_c_and_c.py
# Purpose  :
# Auther   : $Author: PK $


import re
import mmap
import os
import sys
import optparse

def ipFormatChk(ip_str):
     pattern = r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
     if re.match(pattern, ip_str):
        return True
     else:
        return False

#file = open("Windows XP Professional.vmem", "rb")
#size = os.path.getsize("Windows XP Professional.vmem")

#data = mmap.mmap(file.fileno(), size)

def savelist(file,savelist):
 data = open(file,"rb").read()
 with open('memdump2.txt', 'w') as target:
  for m in re.finditer("([\x20-\x7e]{4,})", data):
    target.write(m.group(1))
    target.write("\n")
   
 pattern = r'://([-A-Za-z0-9+&@#/%?=~_()|!:,.;]*[-A-Za-z0-9+&@#/%=~_()|])'
 f = open("memdump2.txt",'r')
 match_urls=re.compile(pattern)
 #re.compile(r"""((?:[a-z][\w-]+:(?:/{1,3}|[a-z0-9])|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|(([^\s()<>]+|(([^\s()<>]+)))*))+(?:(([^\s()<>]+|(([??^\s()<>]+)))*)|[^\s`!()[]{};:'".,<>?<<>>]))""")
 with open(savelist, 'w') as target:
  for line in f.readlines():
      ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)
      url = re.findall(match_urls, line )
      if len(url) > 0:
        if url[0].find("microsoft.com") >=0 or url[0].find("vmware.com") >= 0 or url[0].find("verisign.com") >= 0 or url[0].find("localhost") >= 0 or url[0].find("sysinternals.com") >= 0 or url[0].find("msn.com") >= 0 or url[0].find("google.com") >= 0 or url[0].find("hardware-update.com") >= 0 or url[0].find("cyscape.com") >= 0 or url[0].find("easy_guestbook") >= 0 or url[0].find("cjbasp4.0") >= 0 or url[0].find("windowsmedia.com") >= 0 or url[0].find("w3.org") >= 0 or url[0].find("bpsoft.com") >= 0 or url[0].find("idapro.com") >= 0 or url[0].find("upnp/eventing/") >= 0 or url[0].find("monotype.com") >= 0 or url[0].find("///") >= 0 or url[0].find("chinadfcg.com") >= 0 or url[0].find("ahteam.org") >= 0 or url[0].find("winpcap.org") >= 0 or url[0].find("apsvans.com") >= 0 or url[0].find("nhandan.info") >= 0 or url[0].find("sweetscape.com") >= 0 or url[0].find("LinotypeLibrary.com") >= 0 or url[0].find("ncst.ernet.in") >= 0 or url[0].find("trio.com") >= 0 or url[0].find("ncst.ernet.in") >= 0 or url[0].find("adobe.com") >= 0 or url[0].find("xmlsoap.org") >= 0 or url[0].find("usertrust.com") >= 0 or url[0].find("valicert.com") >= 0 or url[0].find("trustcenter.de") >= 0 or url[0].find("netlock.net") >= 0 or url[0].find("sia.it") >= 0 or url[0].find("certplus.com") >= 0 or url[0].find("digsigtrust.com") >= 0 or url[0].find("tiro.com") >= 0 or url[0].find("entrust.net") >= 0 or url[0].find("thawte.com") >= 0 or url[0].find("macrovision.com") >= 0 or url[0].find("acrobat.com") >= 0 or url[0].find(".verisign") >= 0 or url[0].find("yahoo.com") >= 0 or url[0].find("acrobat.com") >= 0 or url[0].find("macromedia.com") >= 0 or url[0].find("purl.org") >= 0 or url[0].find("aiim.org") >= 0 or url[0].find("iptc.org") >= 0 or url[0].find("sun.com") >= 0 or url[0].find("iec.ch") >= 0 or url[0].find("npes.org") >= 0 or url[0].find("winimage.com") >= 0 or url[0].find("eprint.fede") >= 0 or url[0].find("xfa.org") >= 0 or url[0].find("gwg.org") >= 0 or url[0].find("/C:/") >= 0 or url[0].find("xfa.com") >= 0 or url[0].find("oasis-open.org") >= 0:      
         continue 
        else:
         target.write(url[0])
         target.write("\n")
        
      if len(ip) > 0  and ipFormatChk(ip[0]):
        if ip[0].find("127.0.0.1") >=0 or ip[0].find("2.5.") >=0 or ip[0].find("0.0.0.0") >=0 or ip[0].find("192.168.") >=0 or ip[0].find("0.0") >=0 or ip[0].find("1.3.") >=0 or ip[0].find("5.5.") >=0 or ip[0].find("3.11.") >=0 or ip[0].find("255.255") >=0 or ip[0].find("5.1.1") >=0 or ip[0].find("5.2.2.1") >=0 or ip[0].find("6.1.4.1") >=0 or ip[0].find("6.1.5.5") >=0 or ip[0].find("49.1.7.6") >=0 or ip[0].find("9.16.2.2") >=0 or ip[0].find("193.128.177.124") >=0 or ip[0].find("5.2.2.3") >=0 or ip[0].find("7.7.7.7") >=0 or ip[0].find("1.4.5") >=0 or ip[0].find("169.254.") >=0 or ip[0].find("6.0.1.0") >=0 or ip[0].find("3.3.3.3") >=0 or ip[0].find("1.4.5.0") >=0 or ip[0].find("0.1.2.3") >=0 or ip[0].find("210.177.190.8") >=0 or ip[0].find("38.25.63.10") >=0 or ip[0].find("14.3.2.12") >=0 or ip[0].find("6.6.6.6") >=0 or ip[0].find("1.9.0") >=0 or ip[0].find("2.2.2.2") >=0 or ip[0].find("0.3.5.6") >=0 or ip[0].find("8.8.8.8") >=0 or ip[0].find("0.100.1.25") >=0:
         continue
        else: 
         target.write(ip[0])
         target.write("\n")
        
 f.close()
 os.remove('memdump2.txt')
   
def main(file,loadlist):
 data = open(file,"rb").read()
 with open('memdump2.txt', 'w') as target:
  for m in re.finditer("([\x20-\x7e]{4,})", data):
    target.write(m.group(1))
    target.write("\n")
   
 pattern = r'://([-A-Za-z0-9+&@#/%?=~_()|!:,.;]*[-A-Za-z0-9+&@#/%=~_()|])'
 f = open("memdump2.txt",'r')
 f2 = open(loadlist,'r').read()
 match_urls=re.compile(pattern)
 #re.compile(r"""((?:[a-z][\w-]+:(?:/{1,3}|[a-z0-9])|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|(([^\s()<>]+|(([^\s()<>]+)))*))+(?:(([^\s()<>]+|(([??^\s()<>]+)))*)|[^\s`!()[]{};:'".,<>?<<>>]))""")
 for line in f.readlines():
      ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)
      url = re.findall(match_urls, line )
      if len(url) > 0 and len(url[0]) <200:
        if url[0].find("microsoft.com") >=0 or url[0].find("vmware.com") >= 0 or url[0].find("verisign.com") >= 0 or url[0].find("localhost") >= 0 or url[0].find("sysinternals.com") >= 0 or url[0].find("msn.com") >= 0 or url[0].find("google.com") >= 0 or url[0].find("hardware-update.com") >= 0 or url[0].find("cyscape.com") >= 0 or url[0].find("easy_guestbook") >= 0 or url[0].find("cjbasp4.0") >= 0 or url[0].find("windowsmedia.com") >= 0 or url[0].find("w3.org") >= 0 or url[0].find("bpsoft.com") >= 0 or url[0].find("idapro.com") >= 0 or url[0].find("upnp/eventing/") >= 0 or url[0].find("monotype.com") >= 0 or url[0].find("///") >= 0 or url[0].find("chinadfcg.com") >= 0 or url[0].find("ahteam.org") >= 0 or url[0].find("winpcap.org") >= 0 or url[0].find("apsvans.com") >= 0 or url[0].find("nhandan.info") >= 0 or url[0].find("sweetscape.com") >= 0 or url[0].find("LinotypeLibrary.com") >= 0 or url[0].find("ncst.ernet.in") >= 0 or url[0].find("trio.com") >= 0 or url[0].find("ncst.ernet.in") >= 0 or url[0].find("adobe.com") >= 0 or url[0].find("xmlsoap.org") >= 0 or url[0].find("usertrust.com") >= 0 or url[0].find("valicert.com") >= 0 or url[0].find("trustcenter.de") >= 0 or url[0].find("netlock.net") >= 0 or url[0].find("sia.it") >= 0 or url[0].find("certplus.com") >= 0 or url[0].find("digsigtrust.com") >= 0 or url[0].find("tiro.com") >= 0 or url[0].find("entrust.net") >= 0 or url[0].find("thawte.com") >= 0 or url[0].find("macrovision.com") >= 0 or url[0].find("acrobat.com") >= 0 or url[0].find(".verisign") >= 0 or url[0].find("yahoo.com") >= 0 or url[0].find("acrobat.com") >= 0 or url[0].find("macromedia.com") >= 0 or url[0].find("purl.org") >= 0 or url[0].find("aiim.org") >= 0 or url[0].find("iptc.org") >= 0 or url[0].find("sun.com") >= 0 or url[0].find("iec.ch") >= 0 or url[0].find("npes.org") >= 0 or url[0].find("winimage.com") >= 0 or url[0].find("eprint.fede") >= 0 or url[0].find("xfa.org") >= 0 or url[0].find("gwg.org") >= 0 or url[0].find("/C:/") >= 0 or url[0].find("xfa.com") >= 0 or url[0].find("oasis-open.org") >= 0 or url[0].find("python.org") >= 0 or url[0].find("googlecode.com") >= 0 or url[0].find("java.com") >= 0 or url[0].find("honeynet.org") >= 0:      
         continue 
        else:
         if f2.find(url[0]) < 0:
           print url[0]
        
      if len(ip) > 0 and ipFormatChk(ip[0]) and len(ip[0]) <50:
        if ip[0].find("127.0.0.1") >=0 or ip[0].find("2.5.") >=0 or ip[0].find("0.0.0.0") >=0 or ip[0].find("192.168.") >=0 or ip[0].find("0.0") >=0 or ip[0].find("1.3.") >=0 or ip[0].find("5.5.") >=0 or ip[0].find("3.11.") >=0 or ip[0].find("255.255") >=0 or ip[0].find("5.1.1") >=0 or ip[0].find("5.2.2.1") >=0 or ip[0].find("6.1.4.1") >=0 or ip[0].find("6.1.5.5") >=0 or ip[0].find("49.1.7.6") >=0 or ip[0].find("9.16.2.2") >=0 or ip[0].find("193.128.177.124") >=0 or ip[0].find("5.2.2.3") >=0 or ip[0].find("7.7.7.7") >=0 or ip[0].find("1.4.5") >=0 or ip[0].find("169.254.") >=0 or ip[0].find("6.0.1.0") >=0 or ip[0].find("3.3.3.3") >=0 or ip[0].find("1.4.5.0") >=0 or ip[0].find("0.1.2.3") >=0 or ip[0].find("210.177.190.8") >=0 or ip[0].find("38.25.63.10") >=0 or ip[0].find("14.3.2.12") >=0 or ip[0].find("6.6.6.6") >=0 or ip[0].find("1.9.0") >=0 or ip[0].find("2.2.2.2") >=0 or ip[0].find("0.3.5.6") >=0 or ip[0].find("8.8.8.8") >=0 or ip[0].find("0.100.1.25") >=0:
         continue
        else: 
         if f2.find(ip[0]) < 0:
           print ip[0]
        
 f.close()
 os.remove('memdump2.txt')





if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("-f", "--file", action = "store", type = "string", dest = "configFile")
    parser.add_option("-l", "--list", action = "store", type = "string", dest = "LoadList")
    parser.add_option("-s", "--slist", action = "store", type = "string", dest = "sLoadList")
    options, args = parser.parse_args()
    if options.sLoadList and options.configFile:
      savelist(options.configFile,options.sLoadList)
    elif options.LoadList and options.configFile:
      main(options.configFile,options.LoadList)
    else:
      print 'Usage:----------------------------- \nFirst time(build clear list): python fast_c_and_c.py -f xxxx.vmem -s clearlist.txt\nSecond time(load clear list): python fast_c_and_c.py -f xxxx.vmem -l clearlist.txt\n' 
  
