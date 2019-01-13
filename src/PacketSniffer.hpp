#pragma once

#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <mutex>
#include <thread>
#include <pcap.h>
#include <ctime>
#include <sstream>

#include "Configuration.hpp"
#include "ClientComm.hpp"


class PacketSniffer
{
private:
	struct Packet
	{
		uint8_t prot; // IPPROTO_TCP, IPPROTO_UDP, ..
		time_t tm;
		uint32_t saddr;
		uint16_t sport;
		uint32_t daddr;
		uint16_t dport;

		uint32_t size;
		const char *payload;
	};

	std::mutex &m_control_mutex;
	const Configuration &m_config;
	const ClientComm &m_client_comm;

	boost::thread m_sniffer_thread;
	bool m_run_thread;

	// Name of the device we capture packets on
	std::string m_cap_device;

	uint32_t m_cap_net;
	uint32_t m_cap_mask;

	pcap_t *m_handle{ nullptr };

	// Default filter for npcap if none from config is available
	std::string m_default_filter{ "ip" };
	std::string m_filter{ m_default_filter };

	bool handlePacket(struct pcap_pkthdr *header, const u_char *data, Packet &packet);
	void writePacket(std::stringstream &ss, const u_char *payload, uint32_t size, const Packet &packet);

	std::string getIp(uint32_t addr);
public:
	PacketSniffer(const Configuration &config, const ClientComm &client_comm, std::mutex &control_mutex);

	bool init();
	bool start();
	void stop();

	bool setFilter(const std::string &filter, std::string &error);
	const std::string &getFilter() const { return m_filter; }
};