#pragma once

#include <memory>

#include "Configuration.hpp"
#include "PacketSniffer.hpp"
#include "ClientComm.hpp"


class Agent
{
private:
	std::mutex m_control_mutex;

	Configuration m_config;
	std::shared_ptr<PacketSniffer> m_sniffer;

	ClientComm m_client_comm;

public:
	Agent(const std::string &config_filename);
};
