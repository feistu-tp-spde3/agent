#pragma once

#include <string>
#include <iostream>
#include <mutex>
#include <vector>

#include "Collector.hpp"


class Configuration
{
private:
	std::mutex &m_control_mutex;
	const std::string &m_filename;

	std::vector<Collector> m_collectors;

	// cas po ktorom sa odosielaju data na kolektor
	unsigned int m_send_interval{ 60 };

	// nazov agenta
	std::string m_agent_name;

	// filter pre packet sniffer
	std::string m_agent_filter;

	// parsovanie xml dokumentu
	bool parse();

public:
	Configuration(const std::string &filename, std::mutex &control_mutex);

	const std::vector<Collector> &getCollectors() const { return m_collectors; }
	const std::string &getAgentName() const { return m_agent_name; }
	const std::string &getAgentFilter() const { return m_agent_filter; }
	unsigned int getSendInterval() const { return m_send_interval; }
};
