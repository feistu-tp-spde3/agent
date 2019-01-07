#pragma once

#include <string>
#include <vector>


class ClientComm;


class Collector
{
private:
	std::string m_ip_str;
	std::string m_port_str;

public:
	Collector(const std::string &ip, const std::string &port);

	bool send(const ClientComm &comm, const std::string &data) const;
};
