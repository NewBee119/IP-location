# IP-location
batch query IP location information，批量查询IP地理位置信息  

### 工具详细信息打印  
运行程序：python IP_location.py -h   
Usage: IP_location.py [options]  
Options:  
  -h, --help           show this help message and exit  
  --pcapfile=PCAPFILE  special the pcap file path  
  --IPfile=IPFILE      special the IP list file path  
  -s, --srcIP          parse pcapfile srcIP location  
  -d, --dstIP          parse pcapfile dstIP location  
  
### IP清单文件中IP地理信息的查询  
运行程序：python IP_location.py --IPfile=./iplist.txt  
![Image test](https://github.com/scu-igroup/IP-location/blob/master/image/iplist.png)  

### 批量查询pcap文件中的IP地理信息  
![Image test](https://github.com/scu-igroup/IP-location/blob/master/image/pcap.png)  


