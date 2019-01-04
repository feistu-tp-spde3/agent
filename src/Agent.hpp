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

	void spawnServer(uint16_t port);

	// How many miliseconds to wait until spawning listener server
	static const int SPAWN_SERVER_TIMEOUT{ 1000 };

public:
	Agent(const std::string &config_filename);
};
