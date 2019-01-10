#include <iostream>

#include "Collector.hpp"
#include "ClientComm.hpp"


Collector::Collector(const std::string &ip, const std::string &port) :
	m_ip_str(ip),
	m_port_str(port)
{

}


bool Collector::send(const ClientComm &comm, const std::string &data) const
{
	boost::asio::ip::address addr(boost::asio::ip::make_address(m_ip_str));
	uint16_t port = std::stoi(m_port_str);

	boost::asio::ip::tcp::endpoint endpoint(addr, port);
	boost::asio::ip::tcp::socket receiver(*comm.getIoService());

	try
	{
		receiver.connect(endpoint);
	}
	catch (boost::system::system_error &e)
	{
		std::cerr << "[Collector] Failed to connect to collector " << m_ip_str << ":" << m_port_str << "\n";
		return false;
	}
	
	try
	{
		// Convert data size (32-bit integer) to bytes in little endian order
		struct {
			union {
				uint32_t w;
				char b[sizeof(uint32_t)];
			};
		} len;

		len.w = (uint32_t)data.size();

		// First send a 32-bit unsigned integer representing how many bytes of data we will be sending later
		boost::system::error_code ec;
		size_t no_sent = boost::asio::write(receiver, boost::asio::buffer(len.b), ec);
		if (ec == boost::asio::error::eof)
		{
			std::cerr << "[Collector] Sending length of data to " << m_ip_str << ":" << m_port_str << " returned EOF\n";
			return false;
		}
			
		no_sent = boost::asio::write(receiver, boost::asio::buffer(data), ec);

		boost::this_thread::sleep_for(boost::chrono::seconds(2));

		if (ec == boost::asio::error::eof)
		{
			std::cerr << "[Collector] Sending data to " << m_ip_str << ":" << m_port_str << " returned EOF\n";
			return false;
		}

		if (no_sent)
		{
			std::cout << "[Collector] Sent " << no_sent << " bytes to collector " << m_ip_str << ":" << m_port_str << "\n";
			return true;
		}
		else
		{
			return false;
		}
	}
	catch (boost::system::system_error &e)
	{
		std::cerr << "[Collector] Failed to send to collector " << m_ip_str << ":" << m_port_str << "\n";
		return false;
	}
}
