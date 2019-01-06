#include <boost/chrono.hpp>

#include "Agent.hpp"


Agent::Agent(const std::string &config_filename) :
	m_config{ Configuration(config_filename, m_control_mutex) },
	m_client_comm{ ClientComm(m_config, m_control_mutex) },
	m_sniffer{ std::make_shared<PacketSniffer>(m_config, m_control_mutex) }
{
	// Initialize the sniffing device. This is only done once.
	if (!m_sniffer->init())
	{
		// Probably dont want exceptions here, whatever..
		throw std::runtime_error("Failed to initialize sniffer");
	}

	m_sniffer->start();

	spawnServer(8888);

	int slept = 0;
	while (slept < 60)
	{
		std::string msg = m_client_comm.getMsg();
		if (msg == "ping")
		{
			m_client_comm.sendMsg("pong");
		}
		else if (msg == "start")
		{
			m_sniffer->start();
		}
		else if (msg == "stop")
		{
			std::cout << "[Agent] Stopping sniffer on command\n";
			m_sniffer->stop();
		}
		else if (msg.find("filter//", 0) != std::string::npos)
		{
			std::string filter = msg.substr(msg.find("filter//", 0) + strlen("filter//"), msg.size());

			std::cout << "[Agent] Changing filter to: \"" << filter << "\"\n";
			m_sniffer->setFilter(filter);
		}
		else if (msg == "configlist")
		{
			std::cout << "Sending message\n";
			m_client_comm.sendMsg("hello?");
		}

		m_client_comm.ack();

		boost::this_thread::sleep_for(boost::chrono::seconds(1));
		slept += 1;
	}

	// boost::this_thread::sleep_for(boost::chrono::seconds(30));
}


void Agent::spawnServer(uint16_t port)
{
	boost::thread spawn_thread = boost::thread([this, port]()
	{
		while (true)
		{
			if (m_client_comm.isListenerReady())
			{
				std::cout << "[Agent] Listener ready!\n";
				m_client_comm.waitForClient(port);
			}

			boost::this_thread::sleep_for(boost::chrono::milliseconds(SPAWN_SERVER_TIMEOUT));
		}
	});

	spawn_thread.detach();
}