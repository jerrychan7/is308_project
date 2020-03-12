#pragma once

#include <cstdint>

#define ETH_FRAME_IP		0x0800
#define ETH_FRAME_ARP		0x0806
#define ETH_ADDR_LEN		6
#define ETH_HEAD_LEN		14
#define ETH_MIN_LEN			60
//#define ETH_FRAME_LEN		1514
//// Ethernet MTU (Maximum transfer unit).
//#define ETH_MTU			(ETH_FRAME_LEN - ETH_HEAD_LEN)

#pragma pack (push, 1)
typedef struct {
	uint8_t  dst[ETH_ADDR_LEN];
	uint8_t  src[ETH_ADDR_LEN];
	uint16_t type;
	uint8_t  data[1];
} ethernet_t;
#pragma pack (pop)

// Process an ethernet packet received from the physical layer.
void toEthLayer(const unsigned char* packet, size_t len);

// Send an ethernet packet to the physiscal layer.
int  sendEthPacket(const uint8_t* dstMac, const void* data, size_t len, uint16_t type);
