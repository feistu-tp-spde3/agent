#pragma once

#include <string>
#include <iostream>
#include <mutex>
#include <vector>

#include "pugixml.hpp"
#include "Collector.hpp"


class Configuration
{
private:
	std::string m_filename;
	pugi::xml_document m_xml;

	std::string m_agent_name;
	std::string m_agent_filter;
	std::vector<std::string> m_monitored_processes;
	std::vector<Collector> m_collectors;

	// Interval in which the packets are read from the device (input to pcap_open)
	// In miliseconds
	unsigned int m_sniff_interval{ 100 };

	// https://wiki.wireshark.org/SnapLen
	unsigned int m_sniff_snaplen{ 2048 };

	// Enable promiscuous mode?
	bool m_sniff_promisc{ false };
		
	// If the buffer in which the packets are stored reaches
	// larger size than this (in BYTES), we send it to the collector
	size_t m_send_size{ 65536 };

	// Interval in which the packets are sent to collectors
	// In seconds
	unsigned int m_send_interval{ 10 };

public:
	Configuration();

	bool parse(const std::string &filename);

	bool addMonitoredProcess(const std::string &procname);
	bool removeMonitoredProcess(const std::string &procname);
	bool saveConfig();
	void setAgentFilter(const std::string &filter);

	const std::string &getAgentName() const { return m_agent_name; }
	const std::string &getAgentFilter() const { return m_agent_filter; }
	const std::vector<std::string> &getMonitoredProcesses() const { return m_monitored_processes; }
	const std::vector<Collector> &getCollectors() const { return m_collectors; }
	unsigned int getSniffInterval() const { return m_sniff_interval; }
	unsigned int getSniffSnaplen() const { return m_sniff_snaplen; }
	bool getSniffPromiscMode() const { return m_sniff_promisc;  }
	size_t getSendSize() const { return m_send_size; }
	unsigned int getSendInterval() const { return m_send_interval; }
};
