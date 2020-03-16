#pragma once

#include <cstdint>
#include <string>

// Tool: Converts a network-formatted IP into a string.
std::string ip2s(unsigned long ip);

// Get local information (network format)
// initialize after selecting IF.
uint8_t* getMacAddr();
uint32_t getIPAddr();
uint32_t getNetmaskAddr();
uint32_t getBroadcastAddr();

// Set Npcap's DLL file path and configure DLL lazy loading.
bool loadNpcapDlls();

// Initialize the network interface.
bool showAndSelectIF();
bool selectIFFromIP(unsigned long ip);
void waitingCapturerStop();

// Send a packet
bool sendPacket(uint8_t* data, size_t len);
