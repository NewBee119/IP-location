#!/usr/bin/python
#coding:utf-8
import urllib2
import json
import time
import sys
import dpkt
import socket
from optparse import OptionParser

reload(sys);
sys.setdefaultencoding('utf-8');
 
url = 'http://ip.taobao.com/service/getIpInfo.php?ip='
 
def checkTaobaoIP(ip, fout1, fout2, fout3, fout4):
    try:
        response = urllib2.urlopen(url + ip, timeout=10)
        result = response.readlines()
        data = json.loads(result[0])
        #sys.exit(1)
                      
        if data['data']['country'] == "中国":
            print >>fout1, "%15s: %s-%s-%s-%s" % (ip,data['data']['country'],data['data']['region'],data['data']['city'],data['data']['county'])
        if data['data']['region'] == "四川":
            print >>fout2, "%15s: %s-%s-%s-%s" % (ip,data['data']['country'],data['data']['region'],data['data']['city'],data['data']['county'])
        if data['data']['city'] == "成都":
            print >>fout3, "%15s: %s-%s-%s-%s" % (ip,data['data']['country'],data['data']['region'],data['data']['city'],data['data']['county'])

        return "%15s: %s-%s-%s-%s" % (ip,data['data']['country'],data['data']['region'],data['data']['city'],data['data']['county'])
    except Exception,err:
        print "[error] %s" % err
        print >>fout4, "%s" %ip
        return "%15s: time out" % ip 

def parseIPlistLocation(IPfile):
    try:
        f = open(IPfile, "r+")
        ips = f.readlines()
        f.close()
        fout1 = open("out_country.txt", "wb")
        fout2 = open("out_region.txt", "wb")
        fout3 = open("out_city.txt", "wb")
        fout4 = open("out_error.txt", "wb")
 
        f = open('ip-location.txt', 'w')
        for ip in ips:
            line = checkTaobaoIP(ip.strip(), fout1, fout2, fout3, fout4)
            if line:
                print line.encode('utf-8')
                f.write(line.encode('utf-8')+'\n')
            else:
                print line
                f.write(line+'\n')
        f.close()
        fout1.close()
        fout2.close()
        fout3.close()
        fout4.close()
        print "Done!"
    except Exception,err:
        print "[error] %s" % err

def printPcap(pcap, if_srcIp, if_dstIP):
    flowList = [[] for i in range(20000000)]
    counts = 0
    countFlow = [0]*20000000
    isFlag = 0
    fout = open("out_IP.txt", "wb")   
    for (ts,buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                #print('Non IP Packet type not supported %s' % eth.data.__class__.__name__)
                continue
            ip = eth.data
            if isinstance(ip.data, dpkt.icmp.ICMP):
                #print "Not UDP Packet"  
                continue         #filter tcp packets
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            
            udp = ip.data
            if counts == 0 :
                flowList[0].append(src) 
                flowList[0].append(udp.sport) 
                flowList[0].append(dst) 
                flowList[0].append(udp.dport)
                counts = counts + 1
                countFlow[0] = 1
                '''if flowList[0][2] == '119.23.18.179':'''
                if if_srcIp == True:
                    print >>fout, "%s"% (flowList[0][0])
                    print "%s"% (flowList[0][0])
                if if_dstIP == True:
                    print >>fout, "%s"% (flowList[0][2])
                    print "%s"% (flowList[0][2])
                continue
                #print flowList[0][0],flowList[0][1],flowList[0][2],flowList[0][3]

            if if_srcIp == True:
                for i in range(0, counts):
                    if flowList[i][0] == src:
                        countFlow[i] = countFlow[i] + 1
                        isFlag = 1
                        break
                    else:
                        isFlag = 0
                        continue

            if if_dstIP == True:
                for i in range(0, counts):
                    if flowList[i][2] == dst:
                        countFlow[i] = countFlow[i] + 1
                        isFlag = 1
                        break
                    else:
                        isFlag = 0
                        continue

            if i == counts - 1 and isFlag == 0:
                flowList[counts].append(src) 
                flowList[counts].append(udp.sport) 
                flowList[counts].append(dst) 
                flowList[counts].append(udp.dport)
                '''if flowList[counts][2] == '119.23.18.179':'''  #filter some packets relying on dstIP
                if if_srcIp == True:
                    print >>fout, "%s"% (flowList[counts][0])
                    print "%s"% (flowList[counts][0])
                if if_dstIP == True:
                    print >>fout, "%s"% (flowList[counts][2])
                    print "%s"% (flowList[counts][2])
                    
                countFlow[counts] = 1
                counts = counts + 1 
                
            isFlag = 0    
        except Exception,err:
            print "[error] %s" % err 

    fout.close
     
if __name__ == "__main__":

    #pcap_path = "./3.03.cap " 
    #ip_path = "./iplist.txt" 

    parser = OptionParser()  
    parser.add_option(
        "--pcapfile", dest="pcapfile",
        action='store', type='string',
        help="special the pcap file path",
        default=None
    )

    parser.add_option(
        "--IPfile", dest="IPfile",
        action='store', type='string',
        help="special the IP list file path",
        default=None
    )

    parser.add_option(
        "-s", "--srcIP", action="store_true", 
        help="parse pcapfile srcIP location",
        dest="srcIP", default=False
    )

    parser.add_option(
        "-d", "--dstIP", action="store_true", 
        help="parse pcapfile dstIP location",
        dest="dstIP", default=False
    )
  
    (options, args) = parser.parse_args() 

    '''print usage '''
    #print "usage1,  only parse ip-list location: python IP_location.py --IPfile==./iplist.txt "
    #print "usage2, parse srcIP location in pcap: python IP_location.py -s --pcapfile==./101.pcap "

    if (options.pcapfile is None) and (options.IPfile is None):
        print "please input the file path..."
        sys.exit(0)

    if options.srcIP == True and  options.dstIP == True:
        print "either -s or -d, can not both"
        sys.exit(0)

    print "Let's start!"
    print "------------------------------"

    if options.IPfile is not None:
        parseIPlistLocation(options.IPfile)
        sys.exit(0)

    if options.pcapfile is not None:
        if (options.srcIP or options.dstIP) == False:
            print "choose -s or -d"
            sys.exit(0)
        f = open(options.pcapfile)
        pcap = dpkt.pcap.Reader(f)
        printPcap(pcap, options.srcIP, options.dstIP)
        parseIPlistLocation("./out_IP.txt")
        sys.exit(0)