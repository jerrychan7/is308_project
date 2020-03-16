#include <memory>
#include <mutex>
#include <cstdint>
#include <cstdio>
#include <WinSock2.h>	// ntohs
#include "eth.h"
#include "ip.h"
#include "tcp.h"
#include "tools.h"

extern int showDetail;

// Calculate the TCP checksum.
// p1 buff The TCP packet.
// p2 len The size of the TCP packet.
// p3 src_addr The IP source address (in network format).
// p4 dest_addr The IP destination address (in network format).
// rt The result of the checksum.
uint16_t tcpChecksum(const void* buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr) {
	const uint16_t* buf = (uint16_t*)buff;
	uint16_t* ip_src = (uint16_t*)&src_addr,
		    * ip_dst = (uint16_t*)&dest_addr;
	uint32_t sum = 0;
	size_t length = len;
	// Calculate the sum
	while (len > 1) {
		sum += *buf++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}
	// Add the padding if the packet lenght is odd
	if (len & 1) sum += *((uint8_t*)buf);
	// Add the pseudo-header
	sum += *(ip_src++);    sum += *ip_src;
	sum += *(ip_dst++);    sum += *ip_dst;
	sum += htons(IPPROTO_TCP);
	sum += htons((u_short)length);
	// Add the carries
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	// Return the one's complement of sum
	return (uint16_t)(~sum);
}

#include <vector>
std::vector<tcp_state_t*> tcpList;
std::mutex tcp_mutex;

uint32_t getSeqNum() {
	return htonl((uint32_t)std::chrono::duration_cast<std::chrono::microseconds> (
		std::chrono::high_resolution_clock::now().time_since_epoch()).count());
}

// Dump the TCP packet contents on the console.
inline void dumpTcpPacket(tcp_h* packet, size_t len, in_addr_t ip_src, in_addr_t ip_dst, bool recv = true, bool showData = false) {
	printf(
		"TCP packet %s: %zu(%zu) bytes"
		"\n   sender  = %u.%u.%u.%u:%u"
		"\n   receiver= %u.%u.%u.%u:%u"
		"\n   seq=%u, ack=%u, win=%u"
		"\n   URG:%u ACK:%u PSH:%u RST:%u SYN:%u FIN:%u\n",
		recv ? "received" : "send",
		len - size_t(packet->tcp_hdr_len) * 4, len,

		IP_A(ntohl(ip_src)), IP_B(ntohl(ip_src)),
		IP_C(ntohl(ip_src)), IP_D(ntohl(ip_src)),
		ntohs(packet->tcp_src),

		IP_A(ntohl(ip_dst)), IP_B(ntohl(ip_dst)),
		IP_C(ntohl(ip_dst)), IP_D(ntohl(ip_dst)),
		ntohs(packet->tcp_dst),

		ntohl(packet->tcp_seq_num), ntohl(packet->tcp_ack_num),
		ntohs(packet->tcp_win_size),
		// Dump the flags.
		packet->tcp_urg,
		packet->tcp_ack,
		packet->tcp_psh,
		packet->tcp_rst,
		packet->tcp_syn,
		packet->tcp_fin
	);

	if (showData == false || len - size_t(packet->tcp_hdr_len) * 4 == 0)
		return;
	printf("\n   Data:\n   ");
	uint8_t* data_buf = ((uint8_t*)packet) + ((size_t)(packet->tcp_hdr_len) * 4);
	for (int i = 1; i <= (len - (size_t)packet->tcp_hdr_len * 4); i++) {
		printf("%02X ", data_buf[i - 1]);
		if (i % 16 == 0) printf("\n   ");
		else if (i % 8 == 0) putchar(' ');
	}
	putchar('\n');
}

// Send a TCP packet using the same port as the receiving port.
// p1 ip_to The terget host IP address (in network format).
// p2 port_to The port on which the server receives TCP packets.
// p3 data The data you want to sand.
// p4 len The size of the data.
// rt -1 send fail -2 overtime -3 non memory -4 get RST
int sendTcpPacket(in_addr_t ip_to, uint16_t port_to, const void* data, size_t len) {
	tcp_state_t* tcp_conn = (tcp_state_t*)malloc(sizeof(tcp_state_t));
	if (tcp_conn == NULL) return -3;
	memset(tcp_conn, 0, sizeof(tcp_state_t));

	tcp_conn->state = TCP_SYN_SENT;
	tcp_conn->socket.ip_src = getIPAddr();
	tcp_conn->socket.port_src = htons(port_to);
	tcp_conn->socket.ip_dst = ip_to;
	tcp_conn->socket.port_dst = htons(port_to);


	tcp_h* tcph = new tcp_h;
	memset(tcph, 0, sizeof(tcp_h));
	tcph->tcp_src = htons(port_to);
	tcph->tcp_dst = htons(port_to);
	tcph->tcp_seq_num = tcp_conn->seq_num = getSeqNum();
	tcph->tcp_ack_num = 0;
	tcph->tcp_hdr_len = 5;
	tcph->tcp_syn = 1;
	tcph->tcp_win_size = 0xFFFF;
	tcph->tcp_chk = tcpChecksum(tcph, sizeof(tcp_h), getIPAddr(), ip_to);

	if (showDetail)
		printf("\n [-] Send first handshake (SYN).\n");
	if (showDetail == 2)
		dumpTcpPacket(tcph, sizeof(tcp_h), getIPAddr(), ip_to, false, true);

	for (int i = 0, totalCount = 5; i <= totalCount; ++i) {
		// overtime
		if (i == totalCount) {
			printf(" [!] Time out, send fail.\n");
			tcp_mutex.lock();
			for (auto it = tcpList.begin(); it != tcpList.end(); ++it) {
				if (*it == tcp_conn) {
					tcpList.erase(it);
					break;
				}
			}
			delete tcph; tcph = NULL;
			free(tcp_conn); tcp_conn = NULL;
			tcp_mutex.unlock();
			return -2;
		}
		// send
		if (sendIpPacket(ip_to, tcph, sizeof(tcp_h), 255, IPPROTO_TCP) > 0) {
			tcp_mutex.lock();
			tcpList.push_back(tcp_conn);
			tcp_mutex.unlock();
		}
		else {
			delete tcph; tcph = NULL;
			free(tcp_conn); tcp_conn = NULL;
			return -1;
		}
		// wait
		std::this_thread::sleep_for(std::chrono::seconds(4));
		// read
		tcp_mutex.lock();
		bool rst = true;
		for (auto& s : tcpList) {
			if (s == tcp_conn) {
				rst = false;
				break;
			}
		}
		if (rst == true) {
			tcp_mutex.unlock();
			return -4;
		}
		if (tcp_conn->state == TCP_ESTABLISHED) {
			tcp_mutex.unlock();
			break;
		}
		tcp_mutex.unlock();
		if (i != totalCount - 1 && showDetail)
			printf(" [!] Not get answer. Send again.\n");
	}

	if (showDetail)
		printf(" [-] Sent TCP packet with data.\n");
	delete tcph; tcph = NULL;
	u_char* packet = new u_char[len + sizeof(tcp_h)];
	memset(packet, 0, len + sizeof(tcp_h));
	tcph = (tcp_h*)packet;
	tcph->tcp_src = htons(port_to);
	tcph->tcp_dst = htons(port_to);
	tcph->tcp_seq_num = tcp_conn->seq_num;
	tcph->tcp_ack_num = tcp_conn->ack_num;
	tcph->tcp_hdr_len = 5;
	tcph->tcp_syn = 0;
	tcph->tcp_ack = 1;
	tcph->tcp_win_size = 0xFFFF;
	tcph->tcp_chk = 0;
	memcpy(packet + sizeof(tcp_h), data, len);
	tcph->tcp_chk = tcpChecksum(tcph, len + sizeof(tcp_h), getIPAddr(), ip_to);
	tcp_conn->len = (uint32_t)len;
	if (showDetail == 2)
		dumpTcpPacket((tcp_h*)packet, len + sizeof(tcp_h), getIPAddr(), ip_to, false, true);
	while (sendIpPacket(ip_to, packet, len + sizeof(tcp_h), 255, IPPROTO_TCP) <= 0) {
		printf(" [!] send first packet fail! Try again.\n");
	}
	while (1) {
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		// 收到回应
		if (tcp_conn->seq_num == tcph->tcp_ack_num
			&& tcp_conn->ack_num == htonl(ntohl(tcph->tcp_seq_num) + (u_long)len)
			&& tcp_conn->len == 0) {
			//if (showDetail) printf(" [-] Get a ACK respond.\n");
			break;
		}
	}

	if (showDetail)
		printf(" [-] Send FIN packet.\n");
	tcph->tcp_seq_num = tcp_conn->ack_num;
	tcph->tcp_ack_num = tcp_conn->seq_num;
	tcph->tcp_syn = 0;
	tcph->tcp_ack = 1;
	tcph->tcp_fin = 1;
	tcph->tcp_chk = 0;
	tcph->tcp_chk = tcpChecksum(tcph, sizeof(tcp_h), getIPAddr(), ip_to);
	if (showDetail == 2)
		dumpTcpPacket((tcp_h*)packet, sizeof(tcp_h), getIPAddr(), ip_to, false, true);
	while (sendIpPacket(ip_to, packet, sizeof(tcp_h), 255, IPPROTO_TCP) <= 0) {
		printf(" [!] Send FIN packet fail! Try again.\n");
	}
	if (showDetail)
		printf(" [-] Waiting TCP connection close.\n");
	while (1) {
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		// 收到回应
		bool closed = true;
		tcp_mutex.lock();
		for (auto& s : tcpList) {
			if (s == tcp_conn && s->state != TCP_CLOSED) {
				closed = false;
				//printf("\nConn state: %d\n", s->state);
				break;
			}
		}
		tcp_mutex.unlock();
		if (closed) {
			delete[] packet; packet = NULL;
			return 0;
		}
	}

	delete[] packet; packet = NULL;
	free(tcp_conn); tcp_conn = NULL;
	return 0;
}

// Get a data from a TCP connection.
// p1 port_to The port server want to listen on.
// p2 data The data get from TCP connection. Need delete[] after use.
// rt >=0 data len    -1 non mem
int waitTcpPacket(uint16_t port_to, u_char*& data) {
	printf("\n [-] Waiting a tcp packet on port %u...\n", port_to);
	port_to = htons(port_to);
	tcp_state_t* tcp_conn = NULL;
	size_t dataLen = 0;
	while (1) {
		tcp_mutex.lock();
		for (auto& s : tcpList) {
			//if (s) {
			//	printf("\n%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u = %d\n",
			//		IP_A(ntohl(s->socket.ip_src)), IP_B(ntohl(s->socket.ip_src)),
			//		IP_C(ntohl(s->socket.ip_src)), IP_D(ntohl(s->socket.ip_src)), htons(s->socket.port_src),
			//		IP_A(ntohl(s->socket.ip_dst)), IP_B(ntohl(s->socket.ip_dst)),
			//		IP_C(ntohl(s->socket.ip_dst)), IP_D(ntohl(s->socket.ip_dst)), htons(s->socket.port_dst),
			//		s->state
			//	);
			//}
			if (s && s->socket.ip_dst == getIPAddr() && s->socket.port_dst == port_to
				&& s->state == TCP_ESTABLISHED) {
				tcp_conn = s;
				break;
			}
		}
		tcp_mutex.unlock();
		// 建立连接
		if (tcp_conn != NULL) {
			break;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}
	while (1) {
		if (tcp_conn->state != TCP_ESTABLISHED)
			break;
		if (tcp_conn->data != NULL) {
			tcp_mutex.lock();
			dataLen = tcp_conn->dataLen;
			if (showDetail) {
				u_char* d = new u_char[dataLen + 1];
				memcpy(d, tcp_conn->data, dataLen + 1);
				d[dataLen] = '\0';
				printf(" [+] Get TCP data:\n    [-] %s\n    ", d);
				for (int i = 1; i <= dataLen; ++i) {
					if (i % 16 == 0) printf("\n    ");
					else if (i % 8 == 0) putchar(' ');
					printf("%02x ", tcp_conn->data[i - 1]);
				}
				putchar('\n');
			}
			data = new u_char[dataLen];
			memcpy(data, tcp_conn->data, dataLen);
			free(tcp_conn->data); tcp_conn->data = NULL;
			tcp_conn->dataLen = 0;
			tcp_mutex.unlock();
			break;
		}
		std::this_thread::yield();
	}
	if (showDetail)
		printf(" [+] Waiting TCP connection close.\n");
	while (1) {
		bool closed = true;
		tcp_mutex.lock();
		for (auto& s : tcpList) {
			if (s == tcp_conn && s->state != TCP_CLOSED) {
				closed = false;
				break;
			}
		}
		tcp_mutex.unlock();
		if (closed) {
			return (int)dataLen;
		}
		std::this_thread::yield();
	}
	return 0;
}

// IP layer -> TCP layer. Process a TCP packet from the IP layer
// ip_dst = self host ip
void toTcpLayer(tcp_h* packet, size_t len, in_addr_t ip_src, in_addr_t ip_dst) {
	uint8_t* data_buf = ((uint8_t*)packet) +
		(packet->tcp_hdr_len * sizeof(uint32_t));
	uint16_t chk = tcpChecksum(packet, len, ip_src, ip_dst);
	if (chk) {
		printf("\n [!] TCP checksum error! %04X", chk);
		return;
	}

	tcp_mutex.lock();
#ifdef DEBUG
	dumpTcpPacket(packet, len, ip_src, ip_dst);
#endif

	// find socket
	tcp_state_t* tcp_conn = NULL;
	for (auto& s : tcpList) {
		if (s->state == TCP_CLOSED) {
			continue;
		}
		if ((s->socket.ip_src == ip_src && s->socket.ip_dst == ip_dst && s->socket.port_src == packet->tcp_src && s->socket.port_dst == packet->tcp_dst)
			|| (s->socket.ip_src == ip_dst && s->socket.ip_dst == ip_src && s->socket.port_src == packet->tcp_dst && s->socket.port_dst == packet->tcp_src)) {
			tcp_conn = s;
			break;
		}
	}

	// 接收到第一次握手请求 但我已经是忙碌的状态了
	if ((packet->tcp_syn) && !(packet->tcp_ack)
		&& (tcp_conn != NULL && (tcp_conn->state != TCP_CLOSED && tcp_conn->state != TCP_LISTEN))) {

		if (tcp_conn->state == TCP_SYN_RCVD) {
			tcp_mutex.unlock();
			return;
		}

		// For now only one connection is allowed :-(
		if (showDetail)
			printf(" [!] Only one TCP connection is allowed! Send back a RST packet. ");
		if (showDetail == 2)
			dumpTcpPacket(packet, len, ip_dst, ip_src);

		// Send an RST
		packet->tcp_ack_num = htonl(ntohl(packet->tcp_seq_num) + (u_long)len - (u_long)(packet->tcp_hdr_len) * 4 + 1);
		packet->tcp_seq_num = tcp_conn->seq_num;
		packet->tcp_hdr_len = 5;
		len = sizeof(tcp_h);
		packet->tcp_ack = 1;
		packet->tcp_rst = 1;
		packet->tcp_syn = 0;
		packet->tcp_chk = 0;
		packet->tcp_chk = tcpChecksum(packet, len, ip_dst, ip_src);
		sendIpPacket(ip_src, packet, len, 255, IPPROTO_TCP);

		tcp_mutex.unlock();
		return;
	}
	// 第一次握手 不处于连接状态 空闲 返回第二次握手 建立连接
	if (packet->tcp_syn && !(packet->tcp_ack)
		&& (tcp_conn == NULL || tcp_conn->state == TCP_CLOSED || tcp_conn->state == TCP_LISTEN)) {
		if (showDetail)
			printf(" [-] Received a TCP first handshake packet (SYN).\n");
		if (showDetail == 2)
			dumpTcpPacket(packet, len, ip_dst, ip_src);
		// SYN received!
		// Open a new connection using sockets

		bool socketNotInList = tcp_conn == NULL;
		if (socketNotInList) {
			tcp_conn = (tcp_state_t*)malloc(sizeof(tcp_state_t));
			memset(tcp_conn, 0, sizeof(tcp_state_t));
		}
		tcp_conn->socket.ip_src = ip_src;
		tcp_conn->socket.port_src = packet->tcp_src;
		tcp_conn->socket.ip_dst = ip_dst;
		tcp_conn->socket.port_dst = packet->tcp_dst;
		tcp_conn->state = TCP_SYN_RCVD;

		// Send SYN + ACK (seq+1)
		// Swap source and destination ports
		packet->tcp_dst ^= packet->tcp_src;
		packet->tcp_src ^= packet->tcp_dst;
		packet->tcp_dst ^= packet->tcp_src;

		packet->tcp_ack_num = htonl(ntohl(packet->tcp_seq_num) + 1);
		packet->tcp_seq_num = tcp_conn->seq_num = getSeqNum();
		packet->tcp_syn = 1;
		packet->tcp_ack = 1;
		packet->tcp_chk = 0;
		packet->tcp_chk = tcpChecksum(packet, len, ip_dst, ip_src);
		if (showDetail)
			printf(" [-] Respond a TCP second handshake packet (SYN + ACK).\n");
		if (showDetail == 2)
			dumpTcpPacket(packet, len, ip_dst, ip_src, false);

		if (sendIpPacket(ip_src, packet, len, 255, IPPROTO_TCP) > 0) {
			if (socketNotInList) tcpList.push_back(tcp_conn);
		}

		tcp_mutex.unlock();
		return;
	}
	// 断开重连
	if ((packet->tcp_rst) && (tcp_conn != NULL)) {
		if (showDetail) {
			printf(" [!] Get a RST packet. Disconnect TCP connection.\n");
		}
		if (showDetail == 2) {
			dumpTcpPacket(packet, len, ip_dst, ip_src);
		}
		// Free the TCP connection structure
		for (auto it = tcpList.begin(); it != tcpList.end(); ++it) {
			if (*it == tcp_conn) {
				tcpList.erase(it);
				break;
			}
		}
		free(tcp_conn); tcp_conn = NULL;
		if (showDetail)
			printf(" [-] TCP connection closed!\n");

		tcp_mutex.unlock();
		return;
	}
	// 断开连接请求
	if ((packet->tcp_fin) && (tcp_conn != NULL)) {
		if (tcp_conn->state != TCP_ESTABLISHED) {
			tcp_mutex.unlock();
			return;
		}

		if (showDetail)
			printf(" [-] Get a FIN packet (FIN).\n");
		if (showDetail == 2) {
			dumpTcpPacket(packet, len, ip_dst, ip_src);
		}

		// FIN received!					//
		// Close the connection					//
		// Send ACK (seq+1) and close also our connection	//
		// setting the FIN flag on				//

		// Swap source and destination ports			//
		packet->tcp_dst ^= packet->tcp_src;
		packet->tcp_src ^= packet->tcp_dst;
		packet->tcp_dst ^= packet->tcp_src;

		packet->tcp_ack_num = htonl(ntohl(packet->tcp_seq_num) + (u_long)len - (u_long)(packet->tcp_hdr_len) * 4 + 1);
		packet->tcp_seq_num = tcp_conn->seq_num;
		packet->tcp_hdr_len = 5;
		len = sizeof(tcp_h);
		packet->tcp_fin = 0;
		packet->tcp_ack = 1;
		packet->tcp_chk = 0;
		packet->tcp_chk = tcpChecksum(packet, len, ip_dst, ip_src);

		if (showDetail)
			printf(" [-] Send back a ACK respond.\n");
		if (showDetail == 2)
			dumpTcpPacket(packet, len, ip_dst, ip_src, false);

		if (sendIpPacket(ip_src, packet, len, 255, IPPROTO_TCP) <= 0) {}

		// if I'm server
		if (tcp_conn->socket.ip_src == ip_src) {
			if (showDetail)
				printf(" [-] Send a FIN respond.\n");
			packet->tcp_ack_num = htonl(ntohl(packet->tcp_seq_num) + (u_long)len - (u_long)(packet->tcp_hdr_len) * 4 + 1);
			packet->tcp_seq_num = tcp_conn->seq_num;
			packet->tcp_hdr_len = 5;
			len = sizeof(tcp_h);
			packet->tcp_fin = 1;
			packet->tcp_ack = 1;
			packet->tcp_chk = 0;
			packet->tcp_chk = tcpChecksum(packet, len, ip_dst, ip_src);
			if (showDetail == 2)
				dumpTcpPacket(packet, len, ip_dst, ip_src, false);
			if (sendIpPacket(ip_src, packet, len, 255, IPPROTO_TCP) <= 0) {}
			// Go into the CLOSING state (wait for ACK)
			tcp_conn->state = TCP_CLOSING;
		}
		else {
			tcp_conn->state = TCP_CLOSED;
			for (auto it = tcpList.begin(); it != tcpList.end(); ++it) {
				if (*it == tcp_conn) {
					tcpList.erase(it);
					break;
				}
			}
			free(tcp_conn); tcp_conn = NULL;
			if (showDetail)
				printf(" [-] TCP connection closed!\n");
		}

		tcp_mutex.unlock();
		return;
	}
	// 接收第三次握手 标志已建立连接
	if ((packet->tcp_ack) && tcp_conn && (tcp_conn->state == TCP_SYN_RCVD)) {
		// Connection established!
		if (showDetail)
			printf(" [-] Received a TCP third handshake packet (ACK).\n");
		if (showDetail == 2)
			dumpTcpPacket(packet, len, ip_dst, ip_src);
		tcp_conn->state = TCP_ESTABLISHED;
		if (showDetail)
			printf(" [-] TCP connection established!\n");

		tcp_mutex.unlock();
		return;
	}
	//dumpTcpPacket(packet, len, ip_src, ip_dst, true);
	//putchar('\n');
	//if (tcp_conn != NULL)
	//	printf("%d:%d -> %d:%d = %d, least ack: %ld", tcp_conn->socket.ip_src, tcp_conn->socket.port_src,
	//		tcp_conn->socket.ip_dst, tcp_conn->socket.port_dst, tcp_conn->state, ntohl(tcp_conn->ack_num));

	// 接收第二次握手 发送第三次握手
	if ((packet->tcp_syn) && (packet->tcp_ack)
		&& (tcp_conn != NULL && tcp_conn->state == TCP_SYN_SENT)) {
		if (ntohl(packet->tcp_ack_num) != ntohl(tcp_conn->seq_num) + 1) {
			tcp_mutex.unlock();
			return;
		}
		if (showDetail)
			printf(" [-] Received a TCP second handshake packet (SYN + ACK).\n");
		if (showDetail == 2) {
			dumpTcpPacket(packet, len, ip_dst, ip_src);
		}
		// Swap source and destination ports
		packet->tcp_dst ^= packet->tcp_src;
		packet->tcp_src ^= packet->tcp_dst;
		packet->tcp_dst ^= packet->tcp_src;

		tcp_conn->seq_num = packet->tcp_seq_num;
		tcp_conn->ack_num = packet->tcp_ack_num;

		packet->tcp_seq_num = tcp_conn->ack_num;
		packet->tcp_ack_num = htonl(ntohl(tcp_conn->seq_num) + 1);
		packet->tcp_hdr_len = 5;
		len = sizeof(tcp_h);
		packet->tcp_syn = 0;
		packet->tcp_ack = 1;
		packet->tcp_chk = 0;
		packet->tcp_chk = tcpChecksum(packet, len, ip_dst, ip_src);

		if (showDetail)
			printf(" [-] Respond third hanshake (ACK).\n");
		if (showDetail == 2)
			dumpTcpPacket(packet, len, ip_dst, ip_src, false);

		if (sendIpPacket(ip_src, packet, len, 255, IPPROTO_TCP) <= 0) { }
		tcp_conn->seq_num = packet->tcp_seq_num;
		tcp_conn->ack_num = packet->tcp_ack_num;

		tcp_conn->state = TCP_ESTABLISHED;

		tcp_mutex.unlock();
		return;
	}

	if (tcp_conn != NULL) {
		// In the other cases ACK every packet
		// 接收包
		if ((tcp_conn->state == TCP_ESTABLISHED)) {
			tcp_conn->seq_num = packet->tcp_seq_num;
			tcp_conn->len = uint32_t(len - (size_t)(packet->tcp_hdr_len) * 4);
			tcp_conn->ack_num = packet->tcp_ack_num;

			// Empty packet with ack! Do not reply
			if ((packet->tcp_ack) && ((len - (size_t)(packet->tcp_hdr_len) * 4) == 0)) {
				tcp_mutex.unlock();
				if (showDetail) printf(" [-] Get a ACK echo.\n");
				if (showDetail == 2)
					dumpTcpPacket(packet, len, ip_dst, ip_src, true, true);
				return;
			}
			if (showDetail) printf(" [-] Get a ACK packet.\n");
			if (showDetail == 2) {
				dumpTcpPacket(packet, len, ip_dst, ip_src, true, true);
			}

			if (tcp_conn->data != NULL) {
				free(tcp_conn->data);
				tcp_conn->data = NULL;
				tcp_conn->dataLen = 0;
			}
			tcp_conn->dataLen = len - (size_t)(packet->tcp_hdr_len) * 4;
			tcp_conn->data = (u_char*)malloc(tcp_conn->dataLen);
			if (tcp_conn->data != NULL) {
				memcpy(tcp_conn->data, ((u_char*)packet) + ((size_t)(packet->tcp_hdr_len) * 4), tcp_conn->dataLen);
			}

			// Swap source and destination ports
			packet->tcp_dst ^= packet->tcp_src;
			packet->tcp_src ^= packet->tcp_dst;
			packet->tcp_dst ^= packet->tcp_src;

			// Send an echo packet to acknowledge
			if (showDetail)
				printf(" [-] Send a echo ACK packet.\n");
			packet->tcp_seq_num = tcp_conn->ack_num;
			packet->tcp_ack_num = htonl(ntohl(tcp_conn->seq_num) + tcp_conn->len);
			packet->tcp_hdr_len = 5;
			len = sizeof(tcp_h);
			packet->tcp_ack = 1;
			packet->tcp_chk = 0;
			packet->tcp_chk = tcpChecksum(packet, len, ip_dst, ip_src);
			if (showDetail == 2)
				dumpTcpPacket(packet, len, ip_dst, ip_src, false);
			sendIpPacket(ip_src, packet, len, 255, IPPROTO_TCP);
			tcp_conn->len = 0;
			tcp_conn->seq_num = packet->tcp_seq_num;
			tcp_conn->ack_num = packet->tcp_ack_num;

			tcp_mutex.unlock();
			return;
		}
		// 关闭连接
		if ((tcp_conn->state == TCP_CLOSING)) {
			// ACK received!
			// Free the TCP connection structure
			for (auto it = tcpList.begin(); it != tcpList.end(); ++it) {
				if (*it == tcp_conn) {
					tcpList.erase(it);
					break;
				}
			}
			free(tcp_conn);
			tcp_conn = NULL;
			if (showDetail)
				printf(" [-] Received the final waved packet echo, TCP connection closed!\n");
			if (showDetail == 2)
				dumpTcpPacket(packet, len, ip_dst, ip_src);

			tcp_mutex.unlock();
			return;
		}
	}

	tcp_mutex.unlock();
}
