#include <cstdio>
#include <pcap.h>
#include "mac.h"
#include "ip.h"
#include "sendarp.h"

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	if (argc < 4 || (argc%2)!=0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	addressInfo myAddressInfo(argv[1]);			//initializing adresss information
	for(int i=2;i<argc;i++){
		if(myAddressInfo.arpCache.find(argv[i]) == myAddressInfo.arpCache.end()){
			myAddressInfo.arpCache[argv[i]] = getMacFromIP(handle, myAddressInfo, argv[i]);
		}
	}
	myAddressInfo.printAddressInfo();
	
	for(int i=2;i<argc;i+=2){
		printf("Sending fake ARP response to sender ip %d: %s\n",i/2, argv[i]);
		sendFakeARP(handle, myAddressInfo, argv[i], argv[i+1]);
	}

	pcap_close(handle);
}