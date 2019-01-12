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

	// How many miliseconds to wait until spawning listener server
	static const int SPAWN_COMM_SERVER_WAIT{ 1000 };

public:
	Agent();

	bool createConfiguration(const std::string &filename);
	bool spawnSniffer();
	void spawnCommServer(uint16_t port);
	void run();
};
