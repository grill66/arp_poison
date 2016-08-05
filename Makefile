arp_poison: arp_poison.o
	gcc -o arp_poison arp_poison.o -lpcap

arp_poison.o: arp_poison.c
	gcc -o arp_poison.o -c arp_poison.c

clean:
	rm -f ./*.o 
