#pragma once

#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <mutex>

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

	void writePacket(struct pcap_pkthdr *header, const u_char *data);

public:
	PacketSniffer(const Configuration &config, std::mutex &control_mutex);

	void init();
	void run();

	void stop();
};