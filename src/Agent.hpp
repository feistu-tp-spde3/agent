#pragma once

#include <memory>

#include "json.hpp"
#include "Configuration.hpp"
#include "PacketSniffer.hpp"
#include "ClientComm.hpp"


using json = nlohmann::json;


class Agent
{
private:
	std::mutex m_control_mutex;

	Configuration m_config;
	std::shared_ptr<PacketSniffer> m_sniffer;
	ClientComm m_client_comm;

	// Every command function outputs a bool
	// Only some commands require arguments
	bool cmd_ping();
	bool cmd_start();
	bool cmd_stop();
	bool cmd_filter(const json &msg);
	bool cmd_proc(const json &msg);

	// How many milliseconds to wait until spawning a communication server
	// Communication server should be spawned when right at the start
	// and every time monitor disconnects from it (because comm server only accepts
	// 1 monitor at a time)
	static const int SPAWN_COMM_SERVER_WAIT{ 1000 };

	// Wait for message in the main thread (milliseconds) -- prevent CPU hogging
	static const int MESSAGE_WAIT{ 100 };

public:
	Agent();

	bool createConfiguration(const std::string &filename);
	bool spawnSniffer();
	void spawnCommServer(uint16_t port);
	void run();
};
