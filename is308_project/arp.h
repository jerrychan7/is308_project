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
} arp_t;
#pragma pack (pop)

bool arp_ip_to_mac(in_addr_t dst_ip, uint8_t* dst_mac);
int  send_arp_packet(in_addr_t ip_to, const uint8_t* eth_to, uint16_t arp_op);
void to_arp_layer(arp_t* packet);

void arp_add_cache(in_addr_t ip, uint8_t* mac);
void arp_remove_cache(in_addr_t ip);
void arp_reset_cache();
