LDLIBS=-lpcap

all: send-arp

send-arp: main.o sendarp.o arphdr.o ethhdr.o ip.o mac.o 
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

main.o: main.cpp sendarp.h
	g++ -Wall -c -o main.o main.cpp 

sendarp.o: sendarp.cpp sendarp.h
	g++ -Wall -c -o sendarp.o sendarp.cpp 

clean:
	rm -f send-arp *.o
