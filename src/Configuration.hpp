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
	unsigned int m_send_interval{ 60 };

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
	unsigned int getSendInterval() const { return m_send_interval; }
};
