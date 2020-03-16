#pragma once

#define IP_V4			4	// IP version 4.
#define IP_V6			6	// IP version 6.

#define IP_FRAME_LEN		65535	// Maximum IP frame length.
#define IP_HEAD_MIN_LEN		20		// Minimum IP header length.
#define IP_DEFAULT_TTL		64		// Default TTL (Time To Live).

#define IPPROTO_ICMP	1	// ICMP (Internet Control Message Protocol) packet type.
#define IPPROTO_IGMP	2	// IGMP (Internet Group Message Protocol) packet type.
#define IPPROTO_TCP		6	// TCP (Transmition Control Protocol) packet type.
#define IPPROTO_UDP		17	// UDP (User Datagram Protocol) packet type.

#define IP_TOS_MIN_DELAY	0x10	// Type of service :: Minimum delay.
#define IP_TOS_MAX_THRU		0x08	// Type of service :: Maximum throughput.
#define IP_TOS_MAX_RELY		0x04	// Type of service :: Maximum rely.
#define IP_TOS_MIN_COST		0x02	// Type of service :: Minimum cost.

// Fragment flags
#define IP_FLAG_MF		0x2000	// More Fragments.
#define IP_FLAG_DF		0x4000	// Don't Fragment.
#define IP_FLAG_CE		0x8000	// The CE flag.
#define IP_FLAG_MASK	0x1FFF	// The flag mask.

// Create an IP address in the binary network format from the notation "a.b.c.d".
#define IP_ADDRESS(a, b, c, d)	((a) | (b) << 8 | (c) << 16 | (d) << 24)
// Get the 1st most significant byte of a host-format IP address.
#define IP_A(ip)		((uint8_t) ((ip) >> 24))
// Get the 2nd most significant byte of a host-format IP address.
#define IP_B(ip)		((uint8_t) ((ip) >> 16))
// Get the 3rd most significant byte of a host-format IP address.
#define IP_C(ip)		((uint8_t) ((ip) >>  8))
// Get the less significant byte of a host-format IP address.
#define IP_D(ip)		((uint8_t) ((ip) >>  0))

//// Loopback IP address.
//#define INADDR_LOOPBACK		IP_ADDRESS(127, 0, 0, 1)
//// Null IP address.
//#define INADDR_ANY		IP_ADDRESS(0, 0, 0, 0)
//// Broadcast IP address.
//#define INADDR_BROADCAST	IP_ADDRESS(255, 255, 255, 255)

// IP address type (in binary network format).
typedef uint32_t in_addr_t;

#pragma pack (push, 1)
// The IP packet structure.
typedef struct {
#if __BYTE_ORDER__ == __LITTLE_ENDIAN__
	uint8_t  ip_hdr_len : 4;	// The header length.
	uint8_t  ip_version : 4;	// The IP version.
#else
	uint8_t  ip_version : 4;	// The IP version.
	uint8_t  ip_hdr_len : 4;	// The IP header length.
#endif
	uint8_t  ip_tos;	// Type of Service.
	uint16_t ip_len;	// IP packet length (both data and header).
	uint16_t ip_id;		// Identification.
	uint16_t ip_off;	// Fragment offset.
	uint8_t  ip_ttl;	// Time To Live.
	uint8_t  ip_proto;	// The type of the upper-level protocol.
	uint16_t ip_chk;	// IP header checksum.
	uint32_t ip_src;	// IP source address (in network format).
	uint32_t ip_dst;	// IP destination address (in network format).
} ip_h;
#pragma pack (pop)

// Calculate the IP header checksum.
uint16_t ipChecksum(const void* buf, size_t hdr_len);

void toIpLayer(ip_h* packet);
int  sendIpPacket(uint32_t ip_to, const void* data, size_t len, uint8_t ttl, uint8_t proto);
