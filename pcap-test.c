#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

#include "pcap_header.h"

#define ETHERTYPE_IP 0x0800

int packet_count = 0;

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}


void print_mac(const u_int8_t* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
}

void print_payload(const u_int8_t* payload, int payload_len) {
    int print_len = 0;

    if (payload_len <= 0) {
        printf("Payload is not exist.\n");
        return;
    }

    print_len = payload_len > 20 ? 20 : payload_len;

    printf("Payload: ");
    for (int i = 0; i < print_len; i++) {
        printf("%02x ", payload[i]);
    }
    printf("\n");
}


void parse_packet(const u_char* packet, uint32_t caplen) {
    PacketInfo info;
    init_packet_info(&info);

    if (caplen < info.ethernet_len)
        return;

    info.eth = (struct libnet_ethernet_hdr*)packet;

    if (ntohs(info.eth->ether_type) != ETHERTYPE_IP)
        return;

    info.ip = (struct libnet_ipv4_hdr*)(packet + info.ethernet_len);

    info.ip_len = info.ip->ip_hl * 4;

    if (info.ip_len < 20)
        return;

    if (caplen < info.ethernet_len + info.ip_len)
        return;

    if (info.ip->ip_p != IPPROTO_TCP)
        return;

    info.tcp = (struct libnet_tcp_hdr*)(packet + info.ethernet_len + info.ip_len);

    info.tcp_len = info.tcp->th_off * 4;

    if (info.tcp_len < 20)
        return;

    if (caplen < info.ethernet_len + info.ip_len + info.tcp_len)
        return;

    uint16_t ip_total_len = ntohs(info.ip->ip_len);
    if (ip_total_len < info.ip_len + info.tcp_len)
	    return;
    
    info.payload = packet + info.ethernet_len + info.ip_len + info.tcp_len;
    info.payload_len = ip_total_len - info.ip_len - info.tcp_len;

    printf("====================================\n");

    packet_count++;
    printf("Packet %d\n", packet_count);

    printf("Ethernet src mac: ");
    print_mac(info.eth->ether_shost);
    printf("\n");

    printf("Ethernet dst mac: ");
    print_mac(info.eth->ether_dhost);
    printf("\n");

    printf("IP src: %s\n", inet_ntoa(info.ip->ip_src));
    printf("IP dst: %s\n", inet_ntoa(info.ip->ip_dst));

    printf("TCP src port: %u\n", ntohs(info.tcp->th_sport));
    printf("TCP dst port: %u\n", ntohs(info.tcp->th_dport));

    print_payload(info.payload, info.payload_len);
}



int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
		parse_packet(packet, header->caplen);
	}

	pcap_close(pcap);
	return 0;
}
