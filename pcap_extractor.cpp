#include <cstdio>
#include <cstring>
#include <ctime>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <getopt.h>

FILE * fd = NULL;

struct Info{
    struct time_val{
        int tv_sec;
        int tv_usec;
    } ts;
    bpf_u_int32 pktlen;
    uint8_t src_mac_address[6];
    uint8_t dst_mac_address[6];
    uint8_t src_ip_address[4];
    uint8_t dst_ip_address[4];
    uint8_t src_port[2];
    uint8_t dst_port[2];
    uint8_t protocol;
};

int WriteToFile(Info *info_ptr, FILE *fd){
    //写入格式
    //时间戳 数据包长度 源mac地址 目的mac地址 源ip地址 目的ip地址 协议类型 源端口 目的端口
    //如果协议没有端口信息，则端口都设为0
    fprintf(fd,"%d.%d",info_ptr->ts.tv_sec,info_ptr->ts.tv_usec);
    fprintf(fd," %u",info_ptr->pktlen);
    fprintf(fd," %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",info_ptr->src_mac_address[0],
    info_ptr->src_mac_address[1],
    info_ptr->src_mac_address[2],
    info_ptr->src_mac_address[3],
    info_ptr->src_mac_address[4],
    info_ptr->src_mac_address[5]);
    fprintf(fd," %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",info_ptr->dst_mac_address[0],
    info_ptr->dst_mac_address[1],
    info_ptr->dst_mac_address[2],
    info_ptr->dst_mac_address[3],
    info_ptr->dst_mac_address[4],
    info_ptr->dst_mac_address[5]);
    fprintf(fd," %u.%u.%u.%u",info_ptr->src_ip_address[0],
    info_ptr->src_ip_address[1],
    info_ptr->src_ip_address[2],
    info_ptr->src_ip_address[3]);
    fprintf(fd," %u.%u.%u.%u",info_ptr->dst_ip_address[0],
    info_ptr->dst_ip_address[1],
    info_ptr->dst_ip_address[2],
    info_ptr->dst_ip_address[3]);
    fprintf(fd," %u",info_ptr->protocol);
    int srcp=info_ptr->src_port[0]*256+info_ptr->src_port[1];
    fprintf(fd," %d",srcp);
    int dstp=info_ptr->dst_port[0]*256+info_ptr->dst_port[1];
    fprintf(fd," %d\n",dstp);  
}

void PcapHandler(
    u_char *args,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet_body
)
{
    struct ether_header *eth_header = (struct ether_header *) packet_body;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        Info info;
        info.pktlen = packet_header->len;
        info.ts.tv_sec = packet_header->ts.tv_sec;
        info.ts.tv_usec = packet_header->ts.tv_usec;

        memcpy(info.src_mac_address, eth_header->ether_shost,6);
        memcpy(info.dst_mac_address, eth_header->ether_dhost,6);

        int ethernet_header_length = 14;
        const u_char *ip_header = packet_body + ethernet_header_length;
        int ip_header_length = ((*ip_header) & 0x0F) * 4;
        memcpy(info.src_ip_address, ip_header+12,4);
        memcpy(info.dst_ip_address, ip_header+16,4);

        u_char protocol = *(ip_header + 9);
        info.protocol=protocol;
        if (protocol == IPPROTO_TCP) {
            const u_char *tcp_header = packet_body + ethernet_header_length + ip_header_length;
            //int tcp_header_length = ((*(tcp_header + 12)) & 0xF0) * 4;
            memcpy(info.src_port, tcp_header,2);
            memcpy(info.dst_port, tcp_header+2, 2);
        }else if (protocol == IPPROTO_UDP) {
            const u_char *udp_header = packet_body + ethernet_header_length + ip_header_length;
            memcpy(info.src_port, udp_header,2);
            memcpy(info.dst_port, udp_header+2,2);
        }
        WriteToFile(&info, fd);
    }
}

int main(int argc, char *argv[]) {
    int opt;
    const char* optstring = "d:f:o:";
    char* dev = NULL;
    char* input_file = NULL;
    char* output_file = NULL;
    while ((opt = getopt(argc, argv, optstring)) != -1){
        if(opt == 'd'){
            dev = optarg;
        }else if(opt == 'f'){
            input_file = optarg;
        }else if(opt == 'o'){
            output_file = optarg;
        }
    }

    if ((dev == NULL && input_file == NULL) || (dev && input_file) || (output_file == NULL)) {
        //-d -t有且只有存在一个
        printf("Usage: %s [-d device | -f input_file] -o output_file\n", argv[0]);
        return 1;
    }

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    if (dev != NULL) {
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, error_buffer);
    }
    if (input_file != NULL) {
        handle = pcap_open_offline(input_file, error_buffer);
    }
    if (handle == NULL) {
         fprintf(stderr, "Could not open: %s\n", error_buffer);
         return 4;
    }

    fd=fopen(output_file, "a+");
    if (fd == NULL) {
        printf("Could not open file %s\n", argv[2]);
        return 5;
    }

    pcap_loop(handle, 0, PcapHandler, NULL);

    pcap_close(handle);
    fclose(fd);

    return 0;
}