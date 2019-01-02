#pragma once

#include <string>
#include <vector>
#include <fstream>
#include <boost/process.hpp>


class Configuration;


class Collector
{
private:
#ifdef WIN32
	std::string m_sender_filename{ "HBaseSender.exe" };
#elif __linux__
	std::string m_sender_filename{ "HbaseSender" };
#endif

	std::string m_packets_filename{ "packets.txt" };

	// ip adresa a port kolektora
	std::string m_ip_str;
	std::string m_port_str;

	// timeout(v s)
	unsigned int m_timeout{ 5 };

public:
	Collector(const std::string &, const std::string &);

	// verzia so spustanim procesu
	int send(const Configuration &) const;
};
