#include <boost/chrono.hpp>

#include "Agent.hpp"
#include "ProcessDiscovery.hpp"


Agent::Agent() :
	m_config{ Configuration() },
	m_client_comm{ ClientComm(m_config, m_control_mutex) },
	m_sniffer{ std::make_shared<PacketSniffer>(m_config, m_client_comm, m_control_mutex) }
{
	;
}


bool Agent::createConfiguration(const std::string &filename)
{
	// Error message is printed from the method
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
	ProcessDiscovery pdis;
	for (const std::string &proc : m_config.getMonitoredProcesses())
	{
		std::cout << proc << ": " << pdis.isProcessRunning(proc) << "\n";
	}

	int slept = 0;
	while (slept < 60)
	{
		const std::string &msg = m_client_comm.getMsg();

		if (msg == "ping")
		{
			m_client_comm.sendMsg("pong");
		}
		else if (msg == "start")
		{
			std::cout << "[Agent] Starting sniffer\n";
			m_sniffer->start();
		}
		else if (msg == "stop")
		{
			std::cout << "[Agent] Stopping sniffer\n";
			m_sniffer->stop();
		}
		else if (msg.find("filter//", 0) != std::string::npos)
		{
			std::string filter = msg.substr(msg.find("filter//", 0) + strlen("filter//"), msg.size());

			std::cout << "[Agent] Received new filter: \"" << filter << "\"\n";

			// Report to agent monitor
			std::string error;
			if (!m_sniffer->setFilter(filter, error))
			{
				std::cerr << "[Agent] Failed to change filter: " << error << "\n";
				m_client_comm.sendMsg(error);
			}
			else
			{
				std::cout << "[Agent] Filter changed\n";
				m_client_comm.sendMsg("ok");
			}
		}
		else if (msg == "filter")
		{
			std::cout << "[Agent] Sending filter to monitor\n";
			m_client_comm.sendMsg(m_sniffer->getFilter());
		}

		m_client_comm.ack();

		boost::this_thread::sleep_for(boost::chrono::seconds(1));
		slept += 1;
	}
}