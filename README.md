# pcap

g++ -o pcap_extractor pcap_extractor.cpp -lpcap

./pcap_extractor -f pcap_file -o output_file #从pcap文件读取数据包，提取ip数据包信息到output_file

./pcap_extractor -d dev -o output_file #从网路设备dev捕捉数据包，提取ip数据包信息到output_file
