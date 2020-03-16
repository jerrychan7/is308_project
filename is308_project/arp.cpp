#include <memory>
#include <cstdint>
#include <thread>
#include <mutex>
#include <chrono>
#include <map>
#include <WinSock2.h>	// ntohs
#include "eth.h"
#include "arp.h"
#include "ip.h"		//in_addr_t
#include "tools.h"	//getip getmac

extern int showDetail;

// Broadcast ethernet address.
static uint8_t ethBcast[ETH_ADDR_LEN] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

std::map<in_addr_t, uint8_t[ETH_ADDR_LEN]> arpTable;
std::mutex arpMutex;

inline void dumpArpPacket(arp_h* packet) {
	printf("ARP data:"
		"\n   hard_type:%04X proto_type:%04X hard_size:%u"
		"\n   proto_size:%u  op:%04X"
		"\n   source=%02x:%02x:%02x:%02x:%02x:%02x (%u.%u.%u.%u)"
		"\n   dest  =%02x:%02x:%02x:%02x:%02x:%02x (%u.%u.%u.%u)\n",

		ntohs(packet->arp_hard_type), ntohs(packet->arp_proto_type), packet->arp_hard_size,
		packet->arp_proto_size, ntohs(packet->arp_op),

		packet->arp_eth_source[0], packet->arp_eth_source[1], packet->arp_eth_source[2],
		packet->arp_eth_source[3], packet->arp_eth_source[4], packet->arp_eth_source[5],

		IP_A(ntohl(packet->arp_ip_source)), IP_B(ntohl(packet->arp_ip_source)),
		IP_C(ntohl(packet->arp_ip_source)), IP_D(ntohl(packet->arp_ip_source)),

		packet->arp_eth_dest[0], packet->arp_eth_dest[1], packet->arp_eth_dest[2],
		packet->arp_eth_dest[3], packet->arp_eth_dest[4], packet->arp_eth_dest[5],

		IP_A(ntohl(packet->arp_ip_dest)), IP_B(ntohl(packet->arp_ip_dest)),
		IP_C(ntohl(packet->arp_ip_dest)), IP_D(ntohl(packet->arp_ip_dest))
	);
}

void arpAddCache(in_addr_t ip, uint8_t* mac) {
	arpMutex.lock();
	memcpy(arpTable[ip], mac, 6);
#ifdef DEBUG
	printf("\narp table:\nmac address (ip address):\n");
	for (auto i : arpTable) {
		printf("%02x:%02x:%02x:%02x:%02x:%02x (%u.%u.%u.%u)\n",
			i.second[0], i.second[1], i.second[2], i.second[3], i.second[4], i.second[5],
			IP_A(ntohl(i.first)), IP_B(ntohl(i.first)), IP_C(ntohl(i.first)), IP_D(ntohl(i.first)));
	}
	putchar('\n');
#endif // DEBUG
	arpMutex.unlock();
}

void arpRemoveCache(in_addr_t ip) {
	arpMutex.lock();
	arpTable.erase(ip);
	arpMutex.unlock();
}

void arpResetCache() {
	arpTable.clear();
}

bool arpIP2MAC(in_addr_t dst_ip, uint8_t* dst_mac) {
	// Search the address into the ARP cache
	if (dst_ip == getIPAddr()) {
		arpAddCache(dst_ip, getMacAddr());
	}
	arpMutex.lock();
	if (arpTable.count(dst_ip) != 0) {
		memcpy(dst_mac, arpTable[dst_ip], ETH_ADDR_LEN);
		arpMutex.unlock();
		return true;
	}
	arpMutex.unlock();

	auto initTime = std::chrono::high_resolution_clock::now();
	auto totalTime = initTime + std::chrono::milliseconds(4000);
	auto timeInterval = std::chrono::milliseconds(1000);
	auto time = initTime;
	while (time < totalTime) {
		sendArpPacket(dst_ip, ethBcast, ARP_OP_REQUEST);
		std::this_thread::sleep_for(timeInterval);
		arpMutex.lock();
		if (arpTable.count(dst_ip) != 0) {
			memcpy(dst_mac, arpTable[dst_ip], ETH_ADDR_LEN);
			arpMutex.unlock();
			return true;
		}
		arpMutex.unlock();
		time += timeInterval;
	}
	return false;
}

void toArpLayer(arp_h* packet) {
	switch (ntohs(packet->arp_op)) {
	case ARP_OP_REPLY:
#ifdef DEBUG
		dumpArpPacket(packet);
#endif
		arpAddCache(packet->arp_ip_source, packet->arp_eth_source);
		break;
	case ARP_OP_REQUEST:
	default:
		break;
	}
}

// Send an ARP packet to the ethernet layer.
// p1 ip_to The wanted IP destination address in network format.
// p2 eth_to The ethernet destination address.
// p3 arp_op The ARP operation.
// rt >=0 The number of bytes sent in case of success;  <0 a negative value if an error occurs.
int sendArpPacket(in_addr_t ip_to, const uint8_t* eth_to, uint16_t arp_op) {
	arp_h* packet;
	int tot_len;
	uint8_t* mac_addr;

	packet = (arp_h*)malloc(sizeof(arp_h));
	if (packet == NULL)
		return(-ENOMEM);

	// Create the ARP header
	packet->arp_hard_type = htons(ARPHRD_ETHER);
	packet->arp_proto_type = htons(ETH_FRAME_IP);
	packet->arp_hard_size = ETH_ADDR_LEN;
	packet->arp_proto_size = sizeof(in_addr_t);
	packet->arp_op = htons(arp_op);

	// Copy the MAC address of this host
	if ((mac_addr = getMacAddr()) == NULL)
		// No such device or address!
		return(-ENXIO);

	memcpy(packet->arp_eth_source, mac_addr, ETH_ADDR_LEN);
	// Copy the IP address of this host
	packet->arp_ip_source = getIPAddr();

	// Set the destination MAC address
	memcpy(packet->arp_eth_dest, eth_to, ETH_ADDR_LEN);
	// Set the destination IP
	packet->arp_ip_dest = ip_to;

	// Go to the ethernet layer...
	//tot_len = send_eth_packet(eth_to, packet, sizeof(arp_h), htons(ETH_FRAME_ARP));
	if (showDetail) {
		printf(" [-] Send ARP packet.\n");
	}
	if (showDetail == 2) {
		dumpArpPacket(packet);
	}
	tot_len = sendEthPacket(eth_to, packet, sizeof(arp_h), htons(ETH_FRAME_ARP));
	//#ifdef DEBUG
	//	printf("\n%u bytes ARP packet sent from ethernet layer.\n", tot_len);
	//#endif

		// Free the memory of the packet
	free(packet);
	// Something wrong from at the ethernet layer
	if (tot_len < 0) return tot_len;
	return 0;
}
