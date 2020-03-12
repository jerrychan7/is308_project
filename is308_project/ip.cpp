#include <memory>
#include <cstdint>
#include <cstdio>
#include <WinSock2.h>	// ntohs
#include "eth.h"
#include "arp.h"
#include "tcp.h"
#include "ip.h"
#include "tools.h"

extern int showDetail;

// Calculate the IP header checksum.
// p1 buf The IP header content.
// p2 hdr_len The IP header length.
// rt The result of the checksum.
uint16_t ip_checksum(const void* buf, size_t hdr_len) {
	unsigned long sum = 0;
	const uint16_t* ip1 = (uint16_t*)buf;
	while (hdr_len > 1) {
		sum += *ip1++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		hdr_len -= 2;
	}

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return (uint16_t)(~sum);
}

// Dump an IP packet to the standard output.
// p1 packet The IP packet.
// p2 showData Do you want to display package details in hexadecimal (if len != 0)
void dump_ip_packet(ip_t* packet, bool showData = false) {
	// Dump the IP header
	printf(
		"IP layer received: %zu(%u) bytes"
		"\n  IP Header:"
		"\n    hdr_len:%u, ip_version:%u, ToS:%#04X, tot_len:%u"
		"\n    id:%#010x, off:%#010x, TTL:%u, proto:0x%02x, ip_chk:0x%04X"
		"\n    ip_src:%u.%u.%u.%u, ip_dst:%u.%u.%u.%u\n",

		ntohs(packet->ip_len) - packet->ip_hdr_len * sizeof(uint32_t),
		ntohs(packet->ip_len),

		packet->ip_hdr_len, packet->ip_version, packet->ip_tos,
		ntohs(packet->ip_len), ntohs(packet->ip_id), ntohs(packet->ip_off),
		packet->ip_ttl, packet->ip_proto,
		ntohs(packet->ip_chk),

		IP_A(ntohl(packet->ip_src)), IP_B(ntohl(packet->ip_src)),
		IP_C(ntohl(packet->ip_src)), IP_D(ntohl(packet->ip_src)),

		IP_A(ntohl(packet->ip_dst)), IP_B(ntohl(packet->ip_dst)),
		IP_C(ntohl(packet->ip_dst)), IP_D(ntohl(packet->ip_dst))
	);
	if (!showData || (ntohs(packet->ip_len) - packet->ip_hdr_len * sizeof(uint32_t)) == 0) return;
	// Dump the IP data section
	uint8_t* data = ((uint8_t*)packet + (packet->ip_hdr_len * sizeof(uint32_t)));
	printf("\n  IP Data:\n    ");
	for (int i = 1; i <= (ntohs(packet->ip_len) - packet->ip_hdr_len * sizeof(uint32_t)); i++) {
		if (i % 16 == 0)printf("\n    ");
		else if (i % 8 == 0) putchar(' ');
		printf("%02X", data[i - 1]);
	}
	putchar('\n');
}

// Process an IP packet received from the ethernet layer.
// p1 packet The IP packet.
void to_ip_layer(ip_t* packet) {
	// Calculate the header checksum
	uint16_t chk = ip_checksum(packet, packet->ip_hdr_len * sizeof(uint32_t));
	if (chk) {
		printf(" [!] IP header checksum error! %02x", chk);
		return;
	}

	// Check if we can receive the packet or not
	if (
		(packet->ip_dst != getIPAddr()) &&
		(packet->ip_dst != getBroadcastAddr()) &&
		(packet->ip_dst != INADDR_BROADCAST)
		)
		return;

	// Identify the right protocol
	switch (packet->ip_proto) {
		// TCP (Transmition Control Protocol)
	case IPPROTO_TCP:

#ifdef DEBUG
		// printf("IP layer received a packet from eth layer");
		dump_ip_packet(packet);
#endif // DEBUG
		to_tcp_layer(
			(tcp_t*)((uint8_t*)packet + (packet->ip_hdr_len * sizeof(uint32_t))),
			(ntohs(packet->ip_len) - (packet->ip_hdr_len * sizeof(uint32_t))),
			packet->ip_src,
			packet->ip_dst
		);
		break;
		// ICMP (Internet Control Message Protocol)
	case IPPROTO_ICMP:
		// Internet Group Message Protocol)
	case IPPROTO_IGMP:
		// UDP (User Datagram Protocol)
	case IPPROTO_UDP:
		//dump_ip_packet(packet);
		//printf(" [!] UDP protocol not yet implemented!\n");
		break;
	default:
		//dump_ip_packet(packet);
		//printf("\nUnknown IP protocol!\n");
		break;
	}
}

// Send an IP packet to the ethernet layer.
// p1 ip_to The IP destination address in network format.
// p2 data The buffer of data to be sent.
// p3 len The size of the buffer to be sent.
// p4 ttl TTL (Time To Live).
// p5 proto The upper-layer protocol type.
// rt >=0 The number of bytes sent in case of success; -#EMSGSIZE the packet is too big to be sent;
//    -#ENOMEM cannot allocate the packet structure; -#ENETUNREACH destination address not found;
int send_ip_packet(uint32_t ip_to, const void* data, size_t len, uint8_t ttl, uint8_t proto) {
	uint8_t eth_to[ETH_ADDR_LEN];
	size_t packet_len = len + sizeof(ip_t);
	ip_t* packet;
	int tot_len;

	if (packet_len > IP_FRAME_LEN)
		return(-EMSGSIZE);

	packet = (ip_t*)malloc(packet_len);
	if (packet == NULL) return(-ENOMEM);
	memset(packet, 0, sizeof(ip_t));

	// Create the IP header
	packet->ip_version = IP_V4;
	packet->ip_hdr_len = sizeof(ip_t) / sizeof(uint32_t);
	packet->ip_tos = 0;
	packet->ip_len = htons((u_short)packet_len);
	packet->ip_id = htons(0xDEAD);	// :-)
	packet->ip_off = htons(IP_FLAG_DF | 0);
	packet->ip_ttl = ttl;
	packet->ip_proto = proto;
	packet->ip_chk = 0;
	packet->ip_dst = ip_to;
	packet->ip_src = getIPAddr();
	packet->ip_chk = ip_checksum(packet, sizeof(ip_t));

	// Copy the data into the packet
	memcpy(packet + 1, data, len);

	// Translate the IP address into ethernet address
	// using the ARP protocol.
	if (showDetail) {
		printf(" [-] IP: Geting MAC address...\n");
	}
	if (!arp_ip_to_mac(ip_to, eth_to)) {
		if (showDetail) {
			printf(" [!] IP: Get MAC address fail!\n");
		}
		// The ethernet address was not found!
		return(-ENETUNREACH);
	}
	if (showDetail) {
		printf(" [-] IP: Get MAC address success. Send a IP packet!\n");
	}
	if (showDetail == 2) {
		dump_ip_packet(packet);
	}
	// Go to the ethernet layer...
	tot_len = sendEthPacket(eth_to, packet, packet_len, htons(ETH_FRAME_IP));
	// Free the memory of the packet
	free(packet);
	// Something wrong from at the ethernet layer
	if (tot_len < 0) return(tot_len);
	return (int)(packet_len);
}
