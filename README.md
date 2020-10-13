send-arp
=====

syntax : send-arp \<interface\> \<sender ip\> \<target ip\> \[\<sender ip 2\> \<target ip 2\> ...\]  
sample : send-arp wlan0 192.168.10.2 192.168.10.1

## Results?
Packets transmitted from \<sender ip\> will redirected to your \<interface\>  
Check it out with wireshark
