#include <boost/chrono.hpp>
#include <iostream>
#include <iomanip>


#ifdef __linux__
#include <arpa/inet.h>
#endif

#include "PacketSniffer.hpp"
#include "netdefs.h"


PacketSniffer::PacketSniffer(const Configuration &config, const ClientComm &client_comm, std::mutex &control_mutex) :
	m_config{ config },
	m_client_comm{ client_comm },
	m_control_mutex{ control_mutex }
{
	;
}


bool PacketSniffer::init()
{
	char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
	
	/* Retrieve the device list */
	pcap_if_t *alldevs = nullptr;
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		std::cerr << "[PacketSniffer] Couldn't find capture devices: " << errbuf << "\n";
		return false;
	}

	/* Print the list */
	pcap_if_t *d = nullptr;
	int i = 0;
	int inum;

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
		return false;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	m_cap_device = std::string(d->name);

	/* Find the properties for the device */
	bpf_u_int32 mask;
	bpf_u_int32 net;

	if (pcap_lookupnet(d->name, &net, &mask, errbuf) == -1)
	{
		std::cerr << "[PacketSniffer] Couldn't get netmask for device " << m_cap_device << ": " << errbuf << "\n";
		net = 0;
		mask = 0;
	}

	m_cap_net = net;
	m_cap_mask = mask;
	
	const std::string &cfg_filter = m_config.getAgentFilter();
	if (!cfg_filter.empty())
	{
		m_filter = cfg_filter;
	}

	return true;
}


bool PacketSniffer::start()
{
	char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
	
	// TODO: config: snapshot length?
	m_handle = pcap_open_live(m_cap_device.c_str(), 65535, 1, m_config.getSniffInterval(), errbuf);
	if (m_handle == nullptr) {
		std::cerr << "[PacketSniffer] Couldn't open device " << m_cap_device << ": " << errbuf << "\n";
		return false;
	}

	if (pcap_datalink(m_handle) != DLT_EN10MB)
	{
		std::cerr << "[PacketSniffer] Only Ethernet networks are supported\n";
		return false;
	}

	std::cout << "[PacketSniffer] Starting sniffer, initial filter: \"" << m_filter << "\"\n";

	std::string error;
	if (!setFilter(m_filter, error))
	{
		std::cerr << "[PacketSniffer] Failed to set filter: " << error << "\n";
		return false;
	}

	m_sniffer_thread = boost::thread([this]()
	{
		std::stringstream packetstream;
		
		int res;
		struct pcap_pkthdr *header;
		const u_char *packet_data;

		boost::chrono::time_point<boost::chrono::steady_clock> start = boost::chrono::steady_clock::now();

		while ((res = pcap_next_ex(m_handle, &header, &packet_data)) >= 0)
		{
			if (res == 0)
			{
				// Timeout elapsed
				continue;
			}

			Packet packet;
			if (!handlePacket(header, packet_data, packet))
			{
				continue;
			}

			writePacket(packetstream, packet_data, header->len, packet);

			boost::chrono::time_point<boost::chrono::steady_clock> end = boost::chrono::steady_clock::now();
			boost::chrono::seconds elapsed = boost::chrono::duration_cast<boost::chrono::seconds>(end - start);
			if (elapsed.count() >= m_config.getSendInterval())
			{
				packetstream << "End of Packets File\n";

				for (auto &col : m_config.getCollectors())
				{
					size_t no_sent = 0;
					if (!col.send(m_client_comm, packetstream.str(), no_sent))
					{
						std::cerr << "[PacketSniffer] Failed to send " << packetstream.str().size() << " bytes to collector " << col.getIp() << "\n";
					}
					else
					{
						std::cout << "[PacketSniffer] Sent " << no_sent << " bytes to collector " << col.getIp() << "\n";
					}
				}

				packetstream.str("");
				packetstream.clear();
				start = boost::chrono::steady_clock::now();
			}

			m_control_mutex.lock();
			if (!m_run_thread)
			{
				std::cout << "[PacketSniffer] Stopped sniffer thread\n";
				m_run_thread = false;
				m_control_mutex.unlock();
				break;
			}
			m_control_mutex.unlock();
		}

		pcap_close(m_handle);
	});

	m_control_mutex.lock();
	m_run_thread = true;
	m_control_mutex.unlock();

	m_sniffer_thread.detach();

	return true;
}


bool PacketSniffer::handlePacket(struct pcap_pkthdr *header, const u_char *data, Packet &packet)
{
	const ip_header *ih = (const ip_header *)(data + sizeof(eth_header));
	u_int size_ip = IP_HL(ih) * 4;
	if (size_ip < 20)
	{
		// Invalid IP header length
		return false;
	}

	packet.prot = ih->ip_p;
	packet.tm = header->ts.tv_sec;
	packet.saddr = ih->ip_src.w;
	packet.daddr = ih->ip_dst.w;

	// std::cout << "len: " << header->len << "\n";

	u_short sport, dport;
	const char *payload = nullptr;
	u_int payload_size;
	if (ih->ip_p == IPPROTO_TCP)
	{
		const tcp_header *th = (const tcp_header *)((const u_char *)ih + size_ip);
		u_int size_tcp = TH_OFF(th) * 4;
		if (size_tcp < 20)
		{
			return false;
		}

		sport = ntohs(th->th_sport);
		dport = ntohs(th->th_dport);
		payload = (const char *)(th + size_tcp);
		payload_size = ntohs(ih->ip_len) - (size_ip + size_tcp);

		/*
		printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
			ih->ip_src.b1, ih->ip_src.b2, ih->ip_src.b3, ih->ip_src.b4,
			sport,
			ih->ip_dst.b1, ih->ip_dst.b2, ih->ip_dst.b3, ih->ip_dst.b4,
			dport);
		std::cout << "TCP " << header->len << " " << payload_size << "\n";
		*/
	}
	else if (ih->ip_p == IPPROTO_UDP)
	{
		const udp_header *uh = (const udp_header *)((const u_char *)ih + size_ip);
		sport = ntohs(uh->uh_sport);
		dport = ntohs(uh->uh_dport);
		payload = (const char *)(uh + sizeof(udp_header));
		payload_size = ntohs(uh->uh_len) - sizeof(udp_header);

		/*
		printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
			ih->ip_src.b1, ih->ip_src.b2, ih->ip_src.b3, ih->ip_src.b4,
			sport,
			ih->ip_dst.b1, ih->ip_dst.b2, ih->ip_dst.b3, ih->ip_dst.b4,
			dport);
		std::cout << "UDP " << payload_size << "\n";
		*/
	}
	else
	{
		// Unsupported protocol - we still write some data in $packet
		return false;
	}

	packet.sport = sport;
	packet.dport = dport;

	return true;
}


void PacketSniffer::writePacket(std::stringstream &ss, const u_char *payload, uint32_t size, const Packet &packet)
{
	std::string protocol;

	if (packet.prot == IPPROTO_TCP)
	{
		protocol = "TCP";
	}
	else if (packet.prot == IPPROTO_UDP)
	{
		protocol = "UDP";
	}
	else if (packet.prot == IPPROTO_ICMP)
	{
		protocol = "ICMP";
	}

	ss << std::dec << packet.tm << "\n";
	ss << protocol << "\n";
	ss << getIp(packet.saddr) << "\n";
	ss << getIp(packet.daddr) << "\n";
	ss << packet.sport << "\n";
	ss << packet.dport << "\n";

	for (size_t i = 0; i < size; i++)
	{
		if (i && !(i % 16))
		{
			ss << "\n";
		}

		ss << std::setfill('0') << std::setw(2) << std::hex << std::uppercase << (unsigned)(payload[i]) << " ";
	}

	ss << "\n";
	ss << "End of packet\n\n";
}


std::string PacketSniffer::getIp(uint32_t addr)
{
	std::stringstream s;
	s << (addr & 0xFF) << "." << ((addr >> 8) & 0xFF) << "." << ((addr >> 16) & 0xFF) << "." << ((addr >> 24) & 0xFF);
	return s.str();
}


void PacketSniffer::stop()
{
	m_control_mutex.lock();
	m_run_thread = false;
	m_control_mutex.unlock();
}


bool PacketSniffer::setFilter(const std::string &filter, std::string &error)
{
	if (m_handle == nullptr)
	{
		return false;
	}

	bpf_program fp;

	if (pcap_compile(m_handle, &fp, filter.c_str(), 0, m_cap_net) == -1) {
		error = pcap_geterr(m_handle);
		return false;
	}

	if (pcap_setfilter(m_handle, &fp) == -1) {
		error = pcap_geterr(m_handle);
		return false;
	}

	m_filter = filter;
	return true;
}
