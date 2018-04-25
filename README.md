# IP-location
batch query IP location information，批量查询IP地理位置信息  

### 测试环境  
Ubuntu 16.04 64bit  

### 工具详细信息打印  
运行程序：python IP_location.py -h   
![Image test](https://github.com/scu-igroup/IP-location/blob/master/image/info.png)  
  
### IP清单文件中IP地理信息的查询  
运行程序：python IP_location.py --IPfile=./iplist.txt  
![Image test](https://github.com/scu-igroup/IP-location/blob/master/image/iplist.png)  

### 批量查询pcap文件中的IP地理信息  
运行：python IP_location.py --pcapfile=./out.pcap –s  
![Image test](https://github.com/scu-igroup/IP-location/blob/master/image/pcap.png)  


