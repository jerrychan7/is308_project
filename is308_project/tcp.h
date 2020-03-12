#pragma once

#include <cstdint>
#include "ip.h"		//in_addr_t

#define TCP_CLOSED	    0	// TCP connection closed state.
#define TCP_LISTEN	    1	// TCP listening connection state.
#define TCP_SYN_RCVD	2	// TCP SYN received state.
#define TCP_SYN_SENT	3	// TCP SYN sent state.
#define TCP_ESTABLISHED	4	// TCP connection established state.
#define TCP_CLOSING	    5	// TCP closing state.

// A socket structure.
typedef struct {
	//! IP source address (in network format).
	in_addr_t ip_src;
	//! Source port.
	uint16_t port_src;
	//! IP destination address (in network format).
	in_addr_t ip_dst;
	//! Destination port.
	uint16_t port_dst;
} socket_t;

// A TCP connection states machine structure.
typedef struct {
	int state; // The state of the connection.
	socket_t socket; // The socket used in the connection.
	// 最后一次发送/接收的seq、ack、payloadLen
	uint32_t seq_num;
	uint32_t ack_num;
	uint32_t len;
	// last resv data
	u_char* data;
	size_t dataLen;
} tcp_state_t;

#pragma pack (push, 1)
// TCP packet structure.
typedef struct {
	uint16_t tcp_src;		// Source port.
	uint16_t tcp_dst;		// Destination port.
	uint32_t tcp_seq_num;	// Sequence number.
	uint32_t tcp_ack_num;	// ACK number.
#if __BYTE_ORDER__ == __LITTLE_ENDIAN__
	uint8_t tcp_res1 : 4;	// Reserved (bit 0..3).
	uint8_t tcp_hdr_len : 4;// Header length.
	uint8_t tcp_fin : 1;	// FIN flag.
	uint8_t tcp_syn : 1;	// SYN flag.
	uint8_t tcp_rst : 1;	// RST flag.
	uint8_t tcp_psh : 1;	// PSH flag.
	uint8_t tcp_ack : 1;	// ACK flag.
	uint8_t tcp_urg : 1;	// URG flag.
	uint8_t tcp_res2 : 2;	// Reserved (bit 4..6).
#else
	uint8_t tcp_hdr_len : 4;// Header length.
	uint8_t tcp_res : 6;	// Reserved.
	uint8_t tcp_urg : 1;	// URG flag.
	uint8_t tcp_ack : 1;	// ACK flag.
	uint8_t tcp_psh : 1;	// PSH flag.
	uint8_t tcp_rst : 1;	// RST flag.
	uint8_t tcp_syn : 1;	// SYN flag.
	uint8_t tcp_fin : 1;	// FIN flag.
#endif
	uint16_t tcp_win_size;	// Window size.
	uint16_t tcp_chk;		// TCP checksum.
	uint16_t tcp_urg_ptr;	// Urgent pointer.
} tcp_t;
#pragma pack (pop)

uint16_t tcp_checksum(const void* buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr);
int send_tcp_packet(in_addr_t ip_to, uint16_t port_to, const void* data, size_t len);
void to_tcp_layer(tcp_t* packet, size_t len, in_addr_t ip_src, in_addr_t ip_dst);
int wait_tcp_packet(uint16_t port_to, u_char*& data);
