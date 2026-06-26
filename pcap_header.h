#ifndef PCAP_HEADER_H
#define PCAP_HEADER_H

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>

#define ETHER_ADDR_LEN 6

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define LIBNET_LIL_ENDIAN 1
#define LIBNET_BIG_ENDIAN 0
#else
#define LIBNET_LIL_ENDIAN 0
#define LIBNET_BIG_ENDIAN 1
#endif

struct libnet_tcp_hdr {
    u_int16_t th_sport;
    u_int16_t th_dport;
    u_int32_t th_seq;
    u_int32_t th_ack;

#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4,
             th_off:4;
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4,
             th_x2:4;
#endif

    u_int8_t th_flags;
    u_int16_t th_win;
    u_int16_t th_sum;
    u_int16_t th_urp;
};

struct libnet_ipv4_hdr {
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,
             ip_v:4;
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,
             ip_hl:4;
#endif

    u_int8_t ip_tos;
    u_int16_t ip_len;
    u_int16_t ip_id;
    u_int16_t ip_off;
    u_int8_t ip_ttl;
    u_int8_t ip_p;
    u_int16_t ip_sum;
    struct in_addr ip_src, ip_dst;
};

struct libnet_ethernet_hdr {
    u_int8_t ether_dhost[ETHER_ADDR_LEN];
    u_int8_t ether_shost[ETHER_ADDR_LEN];
    u_int16_t ether_type;
};

typedef struct {
    struct libnet_ethernet_hdr *eth;
    struct libnet_ipv4_hdr *ip;
    struct libnet_tcp_hdr *tcp;

    const u_int8_t *payload;

    uint32_t ethernet_len;
    uint32_t ip_len;
    uint32_t tcp_len;
    int payload_len;
} PacketInfo;

static inline void init_packet_info(PacketInfo *info)
{
    info->eth = NULL;
    info->ip = NULL;
    info->tcp = NULL;
    info->payload = NULL;

    info->ethernet_len = sizeof(struct libnet_ethernet_hdr);
    info->ip_len = 0;
    info->tcp_len = 0;
    info->payload_len = 0;
}


#endif
