#pragma once
// Taken from https://www.tcpdump.org/pcap.html
// https://unix.superglobalmegacorp.com/Net2/newsrc/netinet/if_ether.h.html

#include <cstdint>

#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP 0x0800 
#define ETHERTYPE_ARP 0x0806

// ETHERNET HEADER
struct eth_header
{
	uint8_t ether_dhost[ETHER_ADDR_LEN]; // Destination host address
	uint8_t ether_shost[ETHER_ADDR_LEN]; // Source host address
	uint16_t ether_type; // IP? ARP? RARP? etc
};

union ip_address {
	struct {
		uint8_t b1;
		uint8_t b2;
		uint8_t b3;
		uint8_t b4;
	};
	uint32_t w;
};

// IP HEADER
struct ip_header
{
	uint8_t ip_vhl;			/* version << 4 | header length >> 2 */
	uint8_t ip_tos;			/* type of service */
	uint16_t ip_len;		/* total length */
	uint16_t ip_id;			/* identification */
	uint16_t ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	uint8_t ip_ttl;			/* time to live */
	uint8_t ip_p;			/* protocol */
	uint8_t ip_sum;			/* checksum */
	ip_address ip_src;		/* source and dest address */
	ip_address ip_dst;
	uint32_t op_pad;
};

#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

// TCP HEADER
typedef uint32_t tcp_seq;

struct tcp_header
{
	uint16_t th_sport;		/* source port */
	uint16_t th_dport;		/* destination port */
	tcp_seq th_seq;			/* sequence number */
	tcp_seq th_ack;			/* acknowledgement number */
	uint8_t th_offx2;		/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	uint8_t th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	uint16_t th_win;		/* window */
	uint16_t th_sum;		/* checksum */
	uint16_t th_urp;		/* urgent pointer */
};

// UDP HEADER
struct udp_header
{
	uint16_t uh_sport;		// Source port
	uint16_t uh_dport;		// Destination port
	uint16_t uh_len;		// Datagram length
	uint16_t uh_crc;		// Checksum
};

// ICMP HEADER
struct icmp_header
{
	u_int8_t type;	/* message type */
	u_int8_t code;	/* type sub-code */
	u_int16_t checksum;
	union
	{
		struct
		{
			u_int16_t id;
			u_int16_t sequence;
		} echo;				/* echo datagram */
		u_int32_t gateway;  /* gateway address */
		struct
		{
			u_int16_t __unused;
			u_int16_t mtu;
		} frag; /* path mtu discovery */
	} un;
};

#define ICMP_ECHOREPLY		0	// Echo Reply
#define ICMP_DEST_UNREACH	3	// Destination Unreachable
#define ICMP_SOURCE_QUENCH	4	// Source Quench
#define ICMP_REDIRECT		5	// Redirect (change route)
#define ICMP_ECHO			8	// Echo Request
#define ICMP_TIME_EXCEEDED	11	// Time Exceeded
#define ICMP_PARAMETERPROB	12	// Parameter Problem
#define ICMP_TIMESTAMP		13	// Timestamp Request
#define ICMP_TIMESTAMPREPLY	14	// Timestamp Reply
#define ICMP_INFO_REQUEST	15	// Information Request
#define ICMP_INFO_REPLY		16	// Information Reply
#define ICMP_ADDRESS		17	// Address Mask Request
#define ICMP_ADDRESSREPLY	18	// Address Mask Reply
