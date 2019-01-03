#pragma once

#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <mutex>
#include <pcap.h>

#include "Configuration.hpp"


class PacketSniffer
{
private:
	std::mutex &m_control_mutex;
	const Configuration &m_config;

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

	void writePacket(struct pcap_pkthdr *header, const u_char *data);

public:
	PacketSniffer(const Configuration &config, std::mutex &control_mutex);

	void init();
	void start();
	void stop();

	void setFilter(const std::string &filter);
};