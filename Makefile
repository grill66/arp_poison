arp_spoof: arp_spoof.o
	gcc -o arp_spoof arp_spoof.o -lpcap

arp_spoof.o: arp_spoof.c
	gcc -o arp_spoof.o -c arp_spoof.c

clean:
	rm -f ./*.o 
