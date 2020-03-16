#pragma once

#include <cstdint>
#include "ip.h"		// in_addr_t

#define ARPHRD_ETHER 		1
#define ARP_OP_REQUEST		1
#define ARP_OP_REPLY		2
#define RARP_OP_REQUEST		3
#define RARP_OP_REPLY		4

#pragma pack (push, 1)
typedef struct {
	uint16_t arp_hard_type;
	uint16_t arp_proto_type;
	uint8_t  arp_hard_size;
	uint8_t  arp_proto_size;
	uint16_t arp_op;
	uint8_t  arp_eth_source[6];
	uint32_t arp_ip_source;
	uint8_t  arp_eth_dest[6];
	uint32_t arp_ip_dest;
} arp_h;
#pragma pack (pop)

bool arpIP2MAC(in_addr_t dst_ip, uint8_t* dst_mac);
int  sendArpPacket(in_addr_t ip_to, const uint8_t* eth_to, uint16_t arp_op);
void toArpLayer(arp_h* packet);

void arpAddCache(in_addr_t ip, uint8_t* mac);
void arpRemoveCache(in_addr_t ip);
void arpResetCache();
