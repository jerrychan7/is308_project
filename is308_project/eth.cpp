
#include <memory>
#include <WinSock2.h>	// ntoh?/hton?...
#include "eth.h"
#include "arp.h"
#include "ip.h"
#include "tools.h"		// getmac getip

extern int showDetail;

bool macAddrCmp(uint8_t* m1, uint8_t* m2) {
	return  memcmp(m1, m2, ETH_ADDR_LEN) == 0;
}

unsigned ethCount = 0;
inline void dumpEthPacket(ethernet_t* packet, size_t len) {
	printf("ETH packet received: %zu(%zu) bytes (%u)\n", len - ETH_HEAD_LEN, len, ethCount);
	printf("   MAC DEST   = %02x:%02x:%02x:%02x:%02x:%02x\n",
		packet->dst[0], packet->dst[1], packet->dst[2],
		packet->dst[3], packet->dst[4], packet->dst[5]);
	printf("   MAC SOURCE = %02x:%02x:%02x:%02x:%02x:%02x\n",
		packet->src[0], packet->src[1], packet->src[2],
		packet->src[3], packet->src[4], packet->src[5]);
	printf("   PACK TYPE  = %04x\n", ntohs(packet->type));
}

// Process an ethernet packet received from the physical layer.
void toEthLayer(const unsigned char* packet, size_t len) {
	++ethCount;
	ethernet_t* eh = (ethernet_t*)packet;
	if (!macAddrCmp(eh->dst, getMacAddr()))
		return;
	switch (ntohs(eh->type)) {
	case ETH_FRAME_IP:
#ifdef DEBUG
		dumpEthPacket(eh, len);
#endif
		toIpLayer((ip_h*)eh->data);
		break;
	case ETH_FRAME_ARP:
#ifdef DEBUG
		dumpEthPacket(eh, len);
#endif
		toArpLayer((arp_h*)eh->data);
		break;
	default: break;
	}
}

// Send an ethernet packet to the physiscal layer.
int sendEthPacket(const uint8_t* dstMac, const void* data, size_t len, uint16_t type) {
	uint8_t* packet;
	uint8_t* macAddr;

	// Analyze the packet length (must be less than ETH_MTU)	//
	// TODO: if the packet length if great than ETH_MTU		//
	// perform a packet fragmentation.				//
	//len = MIN(len, ETH_MTU);

	// Create the ethernet packet
	if (!(packet = (uint8_t*)malloc(max(len + ETH_HEAD_LEN, ETH_MIN_LEN))))
		return (-ENOMEM);

	// Get the local mac address
	if ((macAddr = getMacAddr()) == NULL)
		// No such device or address!
		return (-ENXIO);

	// Add the ethernet header to the packet
	memcpy(packet, dstMac, ETH_ADDR_LEN);
	memcpy(packet + ETH_ADDR_LEN, macAddr, ETH_ADDR_LEN);
	memcpy(packet + 2 * ETH_ADDR_LEN, &type, sizeof(uint16_t));

	// Copy the data into the packet
	memcpy(packet + ETH_HEAD_LEN, data, len);

	// Adjust the packet length including the size of the header
	len += ETH_HEAD_LEN;

	// Auto-pad! Send a minimum payload (another 4 bytes are	//
	// sent automatically for the FCS, totalling to 64 bytes)	//
	// It is the minimum length of an ethernet packet.		//
	while (len < ETH_MIN_LEN)
		packet[len++] = '\0';

	if (showDetail) {
		printf(" [-] Send ETH packet.\n");
	}
	if (showDetail == 2) {
		dumpEthPacket((ethernet_t*)packet, len);
	}

	// Go to the physical layer
	len = sendPacket(packet, len) ? len : -1;

	// Free the memory of the packet
	free(packet);

	// Return the bytes transmitted at this level
	return (int)len;
}
