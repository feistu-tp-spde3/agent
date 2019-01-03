#include "PacketSniffer.hpp"
#include "netdefs.h"

#include <iostream>

#include <ctime>

#ifdef __linux__
#include <arpa/inet.h>
#endif


PacketSniffer::PacketSniffer(const Configuration &config, std::mutex &control_mutex) :
	m_config{ config },
	m_control_mutex{ control_mutex }
{
	;
}


void PacketSniffer::init()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;
	pcap_if_t *d;
	bpf_u_int32 mask;
	bpf_u_int32 net;
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

	m_cap_device = std::string(d->name);

	/* Find the properties for the device */
	if (pcap_lookupnet(d->name, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", d->name, errbuf);
		net = 0;
		mask = 0;
	}

	m_cap_net = net;
	m_cap_mask = mask;
}


void PacketSniffer::start()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	
	/* Open the session in promiscuous mode */
	m_handle = pcap_open_live(m_cap_device.c_str(), 512, 1, 10, errbuf);
	if (m_handle == nullptr) {
		fprintf(stderr, "Couldn't open device %s: %s\n", m_cap_device, errbuf);
		return;
	}

	if (pcap_datalink(m_handle) != DLT_EN10MB)
	{
		fprintf(stderr, "Only Ethernet networks are supported");
		return;
	}

	std::cout << "[PacketSniffer] Initial filter: \"" << m_filter << "\"\n";
	setFilter(m_filter);

	// pcap_loop(handle, 0, packetHandler, nullptr);

	m_sniffer_thread = boost::thread([this]()
	{
		struct pcap_pkthdr *header;
		const u_char *packet_data;
		int res;

		while ((res = pcap_next_ex(m_handle, &header, &packet_data)) >= 0)
		{
			if (res == 0)
			{
				// Timeout elapsed
				continue;
			}

			writePacket(header, packet_data);

			if (!m_run_thread)
			{
				m_control_mutex.lock();
				std::cout << "[PacketSniffer] Stopped sniffer thread\n";
				m_run_thread = false;
				m_control_mutex.unlock();
				break;
			}
		}

		pcap_close(m_handle);
	});

	m_control_mutex.lock();
	m_run_thread = true;
	m_control_mutex.unlock();

	m_sniffer_thread.detach();
}

void PacketSniffer::writePacket(struct pcap_pkthdr *header, const u_char *data)
{
	/*

		u_short sport, dport;
	time_t local_tv_sec;

	// local_tv_sec = header->ts.tv_sec;
	// localtime_s(&ltime, &local_tv_sec);
	// strftime(timestr, sizeof(timestr), "%H:%M:%S", &ltime);

	// printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

	*/

	ip_header *ih = nullptr;
	tcp_header *th = nullptr;
	udp_header *uh = nullptr;
	u_int ip_len;
	u_short sport, dport;

	printf("len:%d ", header->len);

	ih = (ip_header *)(data + sizeof(eth_header));
	ip_len = IP_HL(ih) * 4;
	if (ip_len < 20)
	{
		// Invalid IP header length
		;
	}

	if (ih->ip_p == IPPROTO_TCP)
	{
		th = (tcp_header *)((u_char *)ih + ip_len);
		sport = ntohs(th->th_sport);
		dport = ntohs(th->th_dport);

		printf("TCP ");
	}
	else if (ih->ip_p == IPPROTO_UDP)
	{
		uh = (udp_header *)((u_char*)ih + ip_len);
		sport = ntohs(uh->uh_sport);
		dport = ntohs(uh->uh_dport);

		printf("UDP ");
	}
	else
	{
		return;
	}

	uint32_t s = ih->ip_src.w;
	printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
		ih->ip_src.b1, ih->ip_src.b2, ih->ip_src.b3, ih->ip_src.b4,
		sport,
		ih->ip_dst.b1, ih->ip_dst.b2, ih->ip_dst.b3, ih->ip_dst.b4,
		dport);
}


void PacketSniffer::stop()
{
	m_control_mutex.lock();
	std::cout << "[PacketSniffer] Stopping sniffer thread\n";
	m_run_thread = false;
	m_control_mutex.unlock();
}


void PacketSniffer::setFilter(const std::string &filter)
{
	if (m_handle == nullptr)
	{
		return;
	}

	bpf_program fp;

	if (pcap_compile(m_handle, &fp, filter.c_str(), 0, m_cap_net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter.c_str(), pcap_geterr(m_handle));
		return;
	}

	if (pcap_setfilter(m_handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter.c_str(), pcap_geterr(m_handle));
		return;
	}

	m_filter = filter;
}