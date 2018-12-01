#include "Agent.hpp"

#include <boost/chrono.hpp>

Agent::Agent(const std::string &config_filename) :
    m_config{ Configuration(config_filename, m_control_mutex) },
    m_client_comm{ ClientComm(m_config, m_control_mutex) },
    m_sniffer{ std::make_shared<PacketSniffer>() }
{
    m_client_comm.waitForClient(8888);

    m_sniffer->init(m_config); 
    m_sniffer->run(m_config);

    boost::this_thread::sleep_for(boost::chrono::seconds(30));
}
