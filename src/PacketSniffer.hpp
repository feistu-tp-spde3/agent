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

	// Default filter for npcap if e.g. none from config is available
	// For filter syntax manual, see this: https://linux.die.net/man/7/pcap-filter
	std::string m_default_filter{ "ip" };
	std::string m_filter{ m_default_filter };

	// This basically serves as a callback when we sniff a packet from device
	// Parses the packet data depending on what protocol is used etc.
	// Saves relevant data to <packet> variable
	bool handlePacket(struct pcap_pkthdr *header, const u_char *data, Packet &packet);

	// Takes packet data along with Packet structure and formats them to a format
	// we send to the collector
	//
	// NOTE: this format has massive defficincies and needs to be changed in the future
	void writePacket(std::stringstream &ss, const u_char *payload, uint32_t size, const Packet &packet);

	std::string getIp(uint32_t addr);
public:
	PacketSniffer(const Configuration &config, const ClientComm &client_comm, std::mutex &control_mutex);

	// Lists all available devices for sniffing & makes the user choose
	// NOTE: On some computers, there's just 1 device and Npcap is capable
	// of choosing it itself. However, when there are multiple devices present
	// it chooses the first one, which is often not the right one, that's why
	// we make the use choose.
	bool init();

	// Starts the sniffing in a new thread.
	// Whether the thread is running or not is controlled by m_run_thread.
	//
	// This is the thread that sniffs packets, parses them, creates a format to send them
	// in and sends sthem.
	bool start();

	// Just locks the control mutex & sets m_run_thread to false so the thread stops eventually
	void stop();

	bool setFilter(const std::string &filter, std::string &error);
	const std::string &getFilter() const { return m_filter; }
};