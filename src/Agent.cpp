#include <boost/thread.hpp>
#include <boost/chrono.hpp>

#include "Agent.hpp"
#include "ProcessDiscovery.hpp"


using json = nlohmann::json;


Agent::Agent() :
	m_config{ Configuration() },
	m_client_comm{ ClientComm(m_config, m_control_mutex) },
	m_sniffer{ std::make_shared<PacketSniffer>(m_config, m_client_comm, m_control_mutex) }
{
	;
}


bool Agent::createConfiguration(const std::string &filename)
{
	// Error message is printed from the parse method
	return m_config.parse(filename);
}


bool Agent::spawnSniffer()
{
	// Initialize the sniffing device. This is only done once in lifetime of the agent.
	// Error message is printed from the method
	if (!m_sniffer->init())
	{
		return false;
	}

	// Error message is printed from the method
	if (!m_sniffer->start())
	{
		return false;
	}

	// Yes, this function could have had one-line return statement, but it's ugly
	return true;
}


void Agent::spawnCommServer(uint16_t port)
{
	boost::thread spawn_thread = boost::thread([this, port]()
	{
		while (true)
		{
			if (m_client_comm.isListenerReady())
			{
				m_client_comm.waitForClient(port);
			}

			boost::this_thread::sleep_for(boost::chrono::milliseconds(SPAWN_COMM_SERVER_WAIT));
		}
	});

	spawn_thread.detach();
}


void Agent::run()
{
	while (true)
	{
		// This message is supposed to be in JSON
		if (!m_client_comm.getMsg())
		{
			// Without the wait, this loop was hogging 1 full CPU core
			boost::this_thread::sleep_for(boost::chrono::milliseconds(MESSAGE_WAIT));
			continue;
		}

		auto msg = *m_client_comm.getMsg();

		if (msg.empty())
		{
			continue;
		}

		json json_msg;
		try
		{
			json_msg = json::parse(msg);
		}
		catch (json::exception &e)
		{
			std::cerr << "[Agent] Invalid json message received (json exception): " << e.what() << "\n";
			m_client_comm.ack();
			continue;
		}

		// Invalid format of the received JSON message
		if (!json_msg.count("cmd") || !json_msg.count("action") || !json_msg.count("data"))
		{
			std::cerr << "[Agent] Json message has invalid format\n";
			m_client_comm.ack();
			continue;
		}

		const std::string &cmd = json_msg["cmd"];
		bool ok = false;
		if (cmd == "ping")
		{
			ok = cmd_ping();
		}
		else if (cmd == "start")
		{
			ok = cmd_start();
		}
		else if (cmd == "stop")
		{
			ok = cmd_stop();
		}
		else if (cmd == "filter")
		{
			ok = cmd_filter(json_msg);
		}
		else if (cmd == "proc")
		{
			ok = cmd_proc(json_msg);
		}

		if (!ok)
		{
			std::cerr << "[Agent] Failed to process command \"" << cmd << "\"\n";
		}

		m_client_comm.ack();
	}
}


bool Agent::cmd_ping()
{
	json response;
	response["response"] = "pong";
	return m_client_comm.sendMsg(response.dump());
}


bool Agent::cmd_start()
{
	std::cout << "[Agent] Starting sniffer\n";
	return m_sniffer->start();
}


bool Agent::cmd_stop()
{
	std::cout << "[Agent] Stopping sniffer\n";
	m_sniffer->stop();
	return true;
}


bool Agent::cmd_filter(const json &msg)
{
	const std::string &action = msg["action"];
	if (action == "get")
	{
		std::cout << "[Agent] Sending filter to monitor\n";

		json response;
		response["response"] = m_sniffer->getFilter();
		return m_client_comm.sendMsg(response.dump());
	}
	else if (action == "set")
	{
		const std::string &filter = msg["data"];

		std::cout << "[Agent] Received new filter: \"" << filter << "\"\n";

		// Report to agent monitor
		std::string error;
		json response;
		if (!m_sniffer->setFilter(filter, error))
		{
			std::cerr << "[Agent] Failed to change filter: " << error << "\n";
			response["response"] = error;
		}
		else
		{
			std::cout << "[Agent] Filter changed\n";
			response["response"] = "ok";
		}

		m_config.setAgentFilter(filter);

		if (!m_client_comm.sendMsg(response.dump()))
		{
			std::cerr << "[Agent] Failed to send set filter response to monitor\n";
			return false;
		}

		return m_config.saveConfig();
	}

	return true;
}


bool Agent::cmd_proc(const json &msg)
{
	const std::string &action = msg["action"];
	if (action == "get")
	{
		ProcessDiscovery pd;

		json response;

		// This needs to be an empty object in case there are no monitored processes
		// because monitor will think no data was sent
		response["response"] = json::object();
		for (const std::string &procname : m_config.getMonitoredProcesses())
		{
			response["response"][procname] = pd.isProcessRunning(procname);
		}

		return m_client_comm.sendMsg(response.dump());
	}
	else if (action == "add")
	{
		if (!msg["data"].is_string())
		{
			return false;
		}

		const std::string &procname = msg["data"];

		json response;
		if (!m_config.addMonitoredProcess(procname))
		{
			response["response"] = "no";
		}
		else
		{
			response["response"] = "ok";
		}

		return m_client_comm.sendMsg(response.dump());
	}
	else if (action == "del")
	{
		if (!msg["data"].is_string())
		{
			return false;
		}

		const std::string &procname = msg["data"];

		json response;
		if (!m_config.removeMonitoredProcess(procname))
		{
			response["response"] = "no";
		}
		else
		{
			response["response"] = "ok";
		}

		return m_client_comm.sendMsg(response.dump());
	}

	return true;
}