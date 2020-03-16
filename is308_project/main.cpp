#define CLIENT
//#define SERVER
#include <iostream>
#include <chrono>
#include <string>
#include <regex>
#include <WinSock2.h>	// ntohs
#include "tools.h"
#include "tcp.h"
using namespace std;

// eth.dst == dc:53:60:48:41:44 and (eth.type == 0x0806 or eth.type == 0x0800)
// (arp && (eth.addr == dc:53:60:48:41:44 || eth.addr == ff:ff:ff:ff:ff:ff)) || (ip.addr == 10.0.0.95 && tcp)
// (tcp && tcp.port == 12308) || (arp && !(arp.src.proto_ipv4 == 10.0.0.90) && (eth.addr == dc:53:60:48:41:44 || eth.addr == ff:ff:ff:ff:ff:ff))

void showHelp() {
#ifdef CLIENT
	cout << "client [-h|--help|/?] [-d|D] [-p port] ip msg" << endl
		<< "  -h, --help, /?    Show this help." << endl
		<< "  -d, -D            Show the detail of the transmission." << endl
		<< "                        -D will show more detail." << endl
		<< "  -p port           Specifies target port. Default 12308." << endl
		<< "  ip                Specifies target host IP." << endl
		<< "  msg               Message you want to send." << endl;
#endif
#ifdef SERVER
	cout << "server [-h|--help|/?] [-d|D] [port]" << endl
		<< "  -h, --help, /?    Show this help." << endl
		<< "  -d, -D            Show the detail of the transmission." << endl
		<< "                        -D will show more detail." << endl
		<< "  port              The port you want the server to listen on," << endl
		<< "                        default listen on 12308." << endl;
#endif
}

int showDetail = 0;

// My protocol header
#pragma pack (push, 1)
typedef struct {
	uint32_t version;
	uint8_t charset[12];
} pro_h;
#pragma pack (pop)

int main(int argi, char** argv) {
#ifdef CLIENT
	if (argi < 3) {
		cout << "Need target IP address, and message you want to send:" << endl;
		showHelp();
		return -1;
	}
#endif
	uint16_t port = 12308;
	uint32_t ip = IP_ADDRESS(10, 0, 0, 118);
	string msg = "asdf";
	for (int i = 1; i < argi; ++i) {
		string v = argv[i];
		if (v == "-h" || v == "--help" || v == "/?") {
			showHelp();
			return 0;
		}
		if (v == "-d") {
			showDetail = 1;
			continue;
		}
		if (v == "-D") {
			showDetail = 2;
			continue;
		}
#ifdef CLIENT
		if (v == "-p") {
			port = atoi(argv[++i]);
			if (port < 1 || port >= 0x10000) {
				cout << "The port needs to be between 1 and 65535." << endl;
				return -1;
			}
			continue;
		}
		smatch s;
		if (regex_match(v, s
			, regex("^(25[0-5]|2[0-4]\\d|1\\d\\d|\\d\\d|\\d)\\.(25[0-5]|2[0-4]\\d|1\\d\\d|\\d\\d|\\d)\\.(25[0-5]|2[0-4]\\d|1\\d\\d|\\d\\d|\\d)\\.(25[0-5]|2[0-4]\\d|1\\d\\d|\\d\\d|\\d)$"))) {
			int a = atoi(s.str(1).c_str()),
				b = atoi(s.str(2).c_str()),
				c = atoi(s.str(3).c_str()),
				d = atoi(s.str(4).c_str());
			ip = IP_ADDRESS(a, b, c, d);
		}
		else {
			cout << "Error: IP (" << v << ") is invalid. Please enter a valid IP." << endl;
			return -1;
		}
		msg = argv[++i];
#endif
#ifdef SERVER
		smatch s;
		if (regex_match(v, s
			, regex("^(\\d*)$"))) {
			uint16_t t = atoi(s.str(1).c_str());
			if (t <= 0 || t >= 0x10000) {
				cout << "The port needs to be between 1 and 65535." << endl;
				return -1;
			}
			port = t;
		}
#endif
	}

	//ÉèÖÃNpcap DLLÂ·¾¶
	if (!loadNpcapDlls()) {
		cout << " [*]Npcap load faild." << endl;
		return -1;
	}

#ifdef CLIENT
	if (selectIFFromIP(ip) == false) {
		cout << " [!]Connot find a NIC to sand the packet!" << endl;
		return -2;
	}
	cout << " [-]" << ip2s(getIPAddr()) << ":" << port << " -> " << ip2s(ip) << ":" << port << endl;
	cout << " [-]Sending msg: \"" << msg << "\"..." << endl;

	size_t dataLen = sizeof(pro_h) + msg.size() + 1;
	pro_h* p = (pro_h*)malloc(dataLen);
	p->version = 1;
	memcpy(p->charset, "ASNI", 5);
	memcpy(((uint8_t*)p) + sizeof(pro_h), msg.c_str(), msg.size() + 1);

	int r = sendTcpPacket(ip, port, p, dataLen);
	switch (r) {
	case -1:
		printf(" [!]Send Fail!\n");
		break;
	case -2:
		printf(" [!]The connection timed out and could not connect to the server.\n");
		break;
	case -3:
		printf(" [!]Not enough memory.\n");
		break;
	case -4:
		printf(" [!]The server rejected the request.\n");
		break;
	default:
		if (r < 0) printf(" [!] Send fail: Unknown reason! You can use the -d option to debug.\n");
		else printf(" [+]Success.\n");
		break;
	}
#endif
#ifdef SERVER
	if (showAndSelectIF() == false) {
		return -2;
	}
	u_char* data;
	// rt >=0 data len    -1 non mem
	auto len = waitTcpPacket(port, data);
	pro_h* p = (pro_h*)data;
	switch (len) {
	case -1:
		printf(" [!]Not enough memory.\n");
		break;
	default:
		if (len < 0)
			printf(" [!] Send fail: Unknown reason! You can use the -d option to debug.\n");
		else {
			printf(" [+]Success.\n");
			cout << endl << "Receivd a msg, len: " << len - sizeof(pro_h) << endl
				<< "Protocol version: v" << p->version << endl
				<< "Encoding: " << p->charset << endl
				<< "content: " << data + sizeof(pro_h) << endl;
			delete[] data;
		}
		break;
	}
#endif
	waitingCapturerStop();
	return 0;
}
