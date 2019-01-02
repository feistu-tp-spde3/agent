#include "Agent.hpp"

#include <boost/chrono.hpp>

Agent::Agent(const std::string &config_filename) :
	m_config{ Configuration(config_filename, m_control_mutex) },
	m_client_comm{ ClientComm(m_config, m_control_mutex) },
	m_sniffer{ std::make_shared<PacketSniffer>(m_config, m_control_mutex) }
{
	m_client_comm.waitForClient(8888);

	m_sniffer->init();
	m_sniffer->run();

	int slept = 0;
	while (slept < 30)
	{
		std::string msg = m_client_comm.getMsg();
		if (msg == "start")
		{

		}
		else if (msg == "stop")
		{
			m_sniffer->stop();
		}

		m_client_comm.ack();

		boost::this_thread::sleep_for(boost::chrono::seconds(1));
		slept += 1;
	}

	// boost::this_thread::sleep_for(boost::chrono::seconds(30));
}
