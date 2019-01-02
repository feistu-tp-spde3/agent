#include "Collector.hpp"
#include "Configuration.hpp"

#include <chrono>


Collector::Collector(const std::string &ip, const std::string &port) :
	m_ip_str(ip),
	m_port_str(port)
{

}


int Collector::send(const Configuration &cfg) const
{
	std::string args = cfg.getDirectory() + m_packets_filename + " " + m_ip_str + " " + m_port_str;

	boost::process::child sender(m_sender_filename, args);
	sender.wait_for(std::chrono::seconds(m_timeout));
	return sender.exit_code();
}
