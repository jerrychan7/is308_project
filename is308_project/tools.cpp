#include "tools.h"
#include <pcap.h>
#include <thread>
#include <iostream>
#include <cstdio>
#include <tchar.h>
#include <WinSock2.h>
#include <Windows.h>
#include "eth.h"

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "ws2_32.lib")

extern int showDetail;

// Set Npcap's DLL file path and configure DLL lazy loading.
bool LoadNpcapDlls() {
	_TCHAR npcap_dir[512];
	UINT len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, " [X]Error in GetSystemDirectory: %x", GetLastError());
		return false;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, " [X]Error in SetDllDirectory: %x", GetLastError());
		return false;
	}
	std::cout << " [+]Npcap load success." << std::endl;
	return true;
}
// Tool: Converts a network-formatted IP into a string.
std::string ip2s(unsigned long ip) {
	u_char* p = (u_char*)&ip;
	char output[3 * 4 + 3 + 1];
	sprintf_s(output, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	std::string ans = output;
	return ans;
}

// Get local information (network format), initialize after selecting IF.
uint8_t macAddr[6];
uint32_t ipAddr = 0, netmaskAddr = 0, broadcastAddr = 0;
uint8_t* getMacAddr() {
	return (uint8_t*)macAddr;
}
uint32_t getIPAddr() {
	return ipAddr;
}
uint32_t getNetmaskAddr() {
	return netmaskAddr;
}
uint32_t getBroadcastAddr() {
	//return ((~netmaskAddr) | (ipAddr & netmaskAddr));
	return broadcastAddr;
}

// Use the Windows API to obtain the MAC address.
#include <Iphlpapi.h>
#pragma comment(lib,"Iphlpapi.lib")
BYTE* getSelfMac(pcap_if_t* d) {
	ULONG ulSize = 0;
	PIP_ADAPTER_INFO pInfo = NULL;
	int temp = 0;
	temp = GetAdaptersInfo(pInfo, &ulSize);//第一处调用，获取缓冲区大小
	pInfo = (PIP_ADAPTER_INFO)malloc(ulSize);
	temp = GetAdaptersInfo(pInfo, &ulSize);
	std::string t1 = d->name, t2;
	//遍历每一张网卡
	while (pInfo) {
		t2 = pInfo->AdapterName;
		if (t1.find(t2) != std::string::npos) {
			return pInfo->Address;
		}
		pInfo = pInfo->Next;
	}
	return NULL;
}

// Capture and handle packages.
bool _captureFlag = true, _capturerStop = false;
void waitingCapturerStop() {
	_captureFlag = false;
	while (_capturerStop != true) {
		std::this_thread::yield();
	}
}
pcap_t* adhandle = NULL;
void handlePacket(u_char* pkt_data, u_int len) {
	toEthLayer(pkt_data, len);
	free(pkt_data);
}
void snifferPacket() {
	int res;
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
#ifdef DDEBUG
	struct tm* ltime;
	char timestr[16];
	time_t local_tv_sec;
#endif // DDEBUG
	/* Retrieve the packets */
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (_captureFlag != true) break;
		// Timeout elapsed
		if (res == 0) continue;
#ifdef DDEBUG
		///* convert the timestamp to readable format */
		local_tv_sec = header->ts.tv_sec;
		localtime_s((tm* const)&ltime, (const time_t*)&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", (const tm*)&ltime);
		printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
#endif // DDEBUG
		//toEthLayer(pkt_data, header->len);
		auto cpydata = (u_char*)malloc(header->len);
		if (cpydata == NULL) {
			printf(" [!]ERROR non memory!\n");
			return;
		}
		memcpy(cpydata, pkt_data, header->len);
		std::thread handle(handlePacket, cpydata, header->len);
		handle.detach();
	}

	if (res == -1) {
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		_capturerStop = true;
		return;
	}
	pcap_close(adhandle);
	adhandle = NULL;
	_capturerStop = true;
	return;
}

// Initialize the network interface.
bool showAndSelectIF() {
	using std::cout;
	using std::cin;
	using std::endl;
	pcap_if_t* alldevs = NULL;
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		return false;
	}
	int num = 0;
	for (pcap_if_t* d = alldevs; d; d = d->next) {
		cout << num << " " << d->name << "\t" << d->description << "\t";
		for (pcap_addr_t* a = d->addresses; a; a = a->next) {
			switch (a->addr->sa_family) {
				//只关注ipv4
			case AF_INET:
				if (a->addr) {
					cout << ip2s(((struct sockaddr_in*)a->addr)->sin_addr.s_addr);
					continue;
				}
				break;
			default:
				break;
			}
		}
		cout << "\t" << endl;
		num++;
	}
	int listCount = num - 1;

	int selectOption = -1;
	while (1) {
		cout << "Enter the interface number (0~" << listCount << "): ";
#ifdef DEBUG
		selectOption = 0;
		cout << selectOption << endl;
#else
		cin >> selectOption;
#endif
		if (selectOption < 0 || selectOption > listCount) {
			cout << "Interface number out of range." << endl;
		}
		else break;
	}

	/* Jump to the selected adapter */
	auto d = alldevs;
	for (int i = 0; i < selectOption; i++) d = d->next;

	cout << d->name << endl;

	for (pcap_addr_t* a = d->addresses; a; a = a->next) {
		if (a->addr != NULL && a->addr->sa_family == AF_INET) {
			ipAddr = ((struct sockaddr_in*)a->addr)->sin_addr.s_addr;
			netmaskAddr = ((struct sockaddr_in*)a->netmask)->sin_addr.s_addr;
			broadcastAddr = ((struct sockaddr_in*)a->broadaddr)->sin_addr.s_addr;
			//cout << ntohl(ipAddr) << endl << ntohl(netmaskAddr) << endl << ntohl(broadcastAddr) << endl;
			//cout << ip2s(ipAddr) << endl << ip2s(netmaskAddr) << endl << ip2s(broadcastAddr) << endl;
			//return false;
			break;
		}
	}
	memcpy(macAddr, getSelfMac(d), 6);
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
					   // 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		800,			// read timeout
		errbuf			// error buffer
	)) == NULL) {
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap. (%s)\n", d->name, errbuf);
		pcap_freealldevs(alldevs);
		alldevs = NULL;
		return false;
	}
	pcap_freealldevs(alldevs);
	alldevs = NULL;

	if (pcap_set_datalink(adhandle, DLT_EN10MB) != 0) {
		pcap_perror(adhandle, " [!] ERROR: ");
		return false;
	}

	std::thread snifferThread(snifferPacket);
	snifferThread.detach();

	return true;
}
bool selectIFFromIP(unsigned long ip) {
	pcap_if_t* alldevs = NULL, * d;
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		return false;
	}
	int num = 0, selectOption = -1;
	for (d = alldevs; d; d = d->next) {
		for (auto a = d->addresses; a; a = a->next) {
			// 只关注ipv4
			if (a->addr != NULL && a->addr->sa_family == AF_INET) {
				if (a->addr) {
					ipAddr = ((struct sockaddr_in*)a->addr)->sin_addr.s_addr;
					netmaskAddr = ((struct sockaddr_in*)a->netmask)->sin_addr.s_addr;
					broadcastAddr = ((struct sockaddr_in*)a->broadaddr)->sin_addr.s_addr;
					if ((ip & netmaskAddr) == (ipAddr & netmaskAddr)) {
						printf(" [-]Send the packet from the NIC: %s\n", d->name);
						memcpy(macAddr, getSelfMac(d), 6);
						selectOption = num;
						break;
					}
				}
			}
		}
		if (selectOption != -1) break;
		num++;
	}

	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
					   // 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		800,			// read timeout
		errbuf			// error buffer
	)) == NULL) {
		fprintf(stderr, "\n [!]Unable to open the adapter. %s is not supported by Npcap. (%s)\n", d->name, errbuf);
		pcap_freealldevs(alldevs);
		alldevs = NULL;
		return false;
	}
	pcap_freealldevs(alldevs);
	alldevs = NULL;

	if (pcap_set_datalink(adhandle, DLT_EN10MB) != 0) {
		pcap_perror(adhandle, " [!] ERROR: ");
		return false;
	}

	std::thread snifferThread(snifferPacket);
	snifferThread.detach();

	return true;
}

// Send a packet
bool sendPacket(uint8_t* data, size_t len) {
	using namespace std;
	if (pcap_sendpacket(adhandle, data, (int)len) != 0) {
		cout << pcap_geterr(adhandle) << endl;
		return false;
	}
	if (showDetail)
		cout << " [+]send success." << endl;
	return true;
}
