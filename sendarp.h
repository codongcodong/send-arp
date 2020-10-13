#pragma once

Mac getMyMac(const char* ifname);
Ip getMyIp(const char* ifname);
Mac getMacFromIP(pcap_t* handle, const char* ipAddr);
void sendFakeARP(pcap_t* handle, const char* senderIp, const char* targetIp);