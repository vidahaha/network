//
// Created by vidahaha on 2018/6/23.
//

#ifndef NETWORK_PROTOCOL_H
#define NETWORK_PROTOCOL_H

// structs of ethernet, ip, tcp, udp

#define PCAP_HEADER_LEN 24
#define PACKET_HEADER_LEN 16

// ethernet

#define ETHER_LEN           14
#define ETHER_ADDR_LEN      6
#define ETHER_TYPE_LEN      2
#define ETHER_DEST_OFFSET   (0 * ETHER_ADDR_LEN)
#define ETHER_SRC_OFFSET    (1 * ETHER_ADDR_LEN)
#define ETHER_TYPE_OFFSET   (2 * ETHER_ADDR_LEN)
typedef struct _ether_header{
    unsigned char host_dest[ETHER_ADDR_LEN];
    unsigned char host_src[ETHER_ADDR_LEN];
    unsigned short type;
    #define ETHER_TYPE_MIN      0x0600
    #define ETHER_TYPE_IP       0x0800
    #define ETHER_TYPE_ARP      0x0806
    #define ETHER_TYPE_8021Q    0x8100
    #define ETHER_TYPE_BRCM     0x886c
    #define ETHER_TYPE_802_1X   0x888e
    #define ETHER_TYPE_802_1X_PREAUTH 0x88c7
}ether_header;

// ip

/* 4字节的IP地址 */
typedef struct ip_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
} ip_address;

#define IP_LEN_MIN 20

// ipv4 header

typedef struct _ip_header{
    unsigned char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    unsigned char  tos;            // Type of service
    unsigned short tlen;           // Total length
    unsigned short ident;          // Identification
    unsigned short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    unsigned char  ttl;            // Time to live
    unsigned char  proto;          // Protocol
    #define IP_ICMP     1
    #define IP_IGMP     2
    #define IP_TCP      6
    #define IP_UDP      17
    #define IP_IGRP     88
    #define IP_OSPF     89
    unsigned short crc;            // Header checksum
    u_int saddr;          // Source address
    u_int daddr;          // Destination address
}ip_header;

// tcp

#define TCP_LEN_MIN 20
typedef struct _tcp_header
{
    unsigned short th_sport;          // source port
    unsigned short th_dport;          // destination port
    unsigned int   th_seq;            // sequence number field
    unsigned int   th_ack;            // acknowledgement number field
    unsigned char  th_len:4;		   // header length
    unsigned char  th_x2:4;		   // unused
    unsigned char  th_flags;
    #define TH_FIN	0x01
    #define TH_SYN	0x02
    #define TH_RST	0x04
    #define TH_PSH	0x08
    #define TH_ACK	0x10
    #define TH_URG	0x20
    unsigned short th_win;		    /* window */
    unsigned short th_sum;		    /* checksum */
    unsigned short th_urp;		    /* urgent pointer */
}tcp_header;


// udp

#define UDP_LEN 8
typedef struct _udp_header{
    unsigned short uh_sport;          // Source port
    unsigned short uh_dport;          // Destination port
    unsigned short uh_len;            // Datagram length
    unsigned short uh_sum;            // Checksum
}udp_header;





#endif //NETWORK_PROTOCOL_H

