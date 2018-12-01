#include "PacketSniffer.hpp"
#include "netdefs.h"

#include <iostream>
#include <pcap.h>
#include <ctime>

#ifdef __linux__
#include <arpa/inet.h>
#endif

bool PacketSniffer::init(const Configuration& config) {
    return true;
}


void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct tm ltime;
	char timestr[16];
	ip_hdr *ih;
	udp_hdr *uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;

	/* convert the timestamp to readable format */
	// local_tv_sec = header->ts.tv_sec;
	// localtime_s(&ltime, &local_tv_sec);
	// strftime(timestr, sizeof(timestr), "%H:%M:%S", &ltime);

	/* print timestamp and length of the packet */
	// printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);
	printf("len:%d ", header->len);

	/* retireve the position of the ip header */
	ih = (ip_hdr *)(packet + 14); //length of ethernet header

	/* retireve the position of the udp header */
	ip_len = IP_HL(ih) * 4;
	uh = (udp_hdr *)((u_char*)ih + ip_len);

	/* convert from network byte order to host byte order */
	sport = ntohs(uh->sport);
	dport = ntohs(uh->dport);

	/* print ip addresses and udp ports */
	printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
		ih->ip_src.byte1,
		ih->ip_src.byte2,
		ih->ip_src.byte3,
		ih->ip_src.byte4,
		sport,
		ih->ip_dst.byte1,
		ih->ip_dst.byte2,
		ih->ip_dst.byte3,
		ih->ip_dst.byte4,
		dport);
}


void PacketSniffer::run(const Configuration &config) {
	pcap_t *handle;			/* Session handle */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "ip and tcp";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i = 0;
	int inum;

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		return;
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Find the properties for the device */
	if (pcap_lookupnet(d->name, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", d->name, errbuf);
		net = 0;
		mask = 0;
	}

	/* Open the session in promiscuous mode */
	handle = pcap_open_live(d->name, BUFSIZ, 1, 10, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", d->name, errbuf);
		return;
	}

	if (pcap_datalink(handle) != DLT_EN10MB)
	{
		fprintf(stderr, "Only Ethernet networks are supported");
		return;
	}

	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return;
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return;
	}
	/* Grab a packet */
	// packet = pcap_next(handle, &header);
	/* Print its length */
	// printf("Jacked a packet with length of [%d]\n", header.len);

	// print_packet_info(packet, header);
	//readPacket(packet, header);

	pcap_loop(handle, 0, packetHandler, nullptr);
	std::cout << "hello?\n";

	/* And close the session */
	pcap_close(handle);

	return;
}