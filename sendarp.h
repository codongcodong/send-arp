#pragma once

#include <pcap.h>
#include "mac.h"
#include "ip.h"
#include <map>
#include <string>

class addressInfo {
public:
    Mac myMac;
    Ip myIp;
    std::map<std::string,Mac> arpCache;

    Mac getMyMac(const char* ifname);
    Ip getMyIp(const char* ifname);

    void printAddressInfo(void){
        printf("myMac: %s\n",myMac.operator std::string().c_str());
        printf("myIp: %s\n",myIp.operator std::string().c_str());
        puts("");
    }

    addressInfo(const char* ifname){
        myMac = getMyMac(ifname);
        myIp = getMyIp(ifname);
    };
};

Mac getMacFromIP(pcap_t* handle, addressInfo myAddressInfo, const char* ipAddr);
void sendFakeARP(pcap_t* handle, addressInfo myAddressInfo, const char* senderIp, const char* targetIp);