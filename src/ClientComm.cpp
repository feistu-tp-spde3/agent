#include <boost/chrono.hpp>

#include "ClientComm.hpp"
#include "Configuration.hpp"


ClientComm::ClientComm(Configuration &config, std::mutex &control_mutex) :
	m_config{ config },
	m_control_mutex{ control_mutex },
	m_io_service{ std::make_shared<boost::asio::io_service>() }
{
	;
}


void ClientComm::waitForClient(uint16_t listener_port)
{
	m_listener_thread = boost::thread([this, listener_port]()
	{
		std::cout << "[ClientComm] Launching communication thread on port " << listener_port << std::endl;

		boost::system::error_code error;

		// This can throw an exception if an agent is already running
		// TODO
		boost::asio::ip::udp::socket listener(*m_io_service, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), listener_port));
		boost::asio::ip::udp::endpoint sender_endpoint;
		
		listener.set_option(boost::asio::socket_base::broadcast(true));

		int monitor_port = -1;
		char buffer[MAX_BUFFER_SIZE] = { 0 };
		bool msg_received = false;

		m_control_mutex.lock();
		m_listener_ready = false;
		m_control_mutex.unlock();

		while (!msg_received)
		{
			size_t no_received = 0;

			try
			{
				no_received = listener.receive_from(boost::asio::buffer(buffer, MAX_BUFFER_SIZE), sender_endpoint);
			}
			catch (std::exception &e)
			{
				std::cout << "[ClientComm] Exception: " << e.what() << std::endl;
			}

			if (no_received)
			{
				std::string message(buffer, no_received);
				std::cout << "[ClientComm] Message received: \"" << message << "\"\n";

				if (message.find("agentSearch", 0) != std::string::npos)
				{
					listener.close();

					size_t delim = message.find("/", 0);
					if (delim)
					{
						msg_received = true;
						monitor_port = std::stoi(message.substr(delim + 1, message.size() - delim));
					}
					else
					{
						std::cerr << "[ClientComm] Invalid search message received\n";
					}
				}
			}

			boost::this_thread::sleep_for(boost::chrono::milliseconds(100));
		}

		if (msg_received && monitor_port != -1)
		{
			if (!connect(sender_endpoint.address(), monitor_port))
			{
				m_control_mutex.lock();
				m_listener_ready = true;
				m_control_mutex.unlock();
			}
		}
	});

	m_listener_thread.detach();
}


bool ClientComm::connect(const boost::asio::ip::address &ip, uint16_t port)
{
	std::cout << "[ClientComm] Establishing connection with monitor" << std::endl;
	boost::this_thread::sleep_for(boost::chrono::milliseconds(CONNECT_WAIT));

	boost::asio::ip::tcp::endpoint endpoint(ip, port);

	m_client.reset();
	m_client = std::make_shared<boost::asio::ip::tcp::socket>(*m_io_service);

	try
	{
		m_client->connect(endpoint);
	}
	catch (std::exception &e)
	{
		std::cerr << "[ClientComm] Failed to establish TCP connection to client: " << e.what() << "\n";
		return false;
	}

	if (!m_client->is_open())
	{
		return false;
	}

	const std::string &agent_name = m_config.getAgentName();
	const std::string msg = "agentName/" + agent_name;

	// Send identification message to monitor
	boost::system::error_code error;
	size_t no_sent = boost::asio::write(*m_client, boost::asio::buffer(msg), error);
	if (no_sent)
	{
		std::cout << "[ClientComm] Sent identification mesage \"" << msg << "\" to monitor\n";
	}
	else
	{
		std::cerr << "[ClientComm] Failed to send identification message, sent " << no_sent << " bytes instead of " << msg.size() << "\n";
		return false;
	}

	boost::thread t = boost::thread([this]()
	{
		while (true)
		{
			try
			{
				char buffer[MAX_BUFFER_SIZE] = { 0 };
				boost::system::error_code ec;
				size_t received = m_client->read_some(boost::asio::buffer(buffer), ec);

				// When the client drops, the error code is different across platforms:
				// Windows: boost::asio::error::connection_reset
				// Linux: boost::asio::error::eof
				if (ec == boost::asio::error::eof || ec == boost::asio::error::connection_reset)
				{
					std::cout << "[ClientComm] Client dropped\n";
					m_control_mutex.lock();
					m_listener_ready = true;
					m_control_mutex.unlock();
					break;
				}

				if (received)
				{
					m_control_mutex.lock();
					m_client_msg = std::make_shared<std::string>(buffer, received);
					std::cout << "[ClientComm] Message received: \"" << *m_client_msg << "\"\n";
					m_control_mutex.unlock();
				}
			}
			catch (boost::system::system_error &e)
			{
				std::cerr << "[ClientComm] Message couldn't be sent: " << e.what() << std::endl;
			}
		}
	});

	t.detach();
	return true;
}


void ClientComm::ack()
{
	m_control_mutex.lock();
	if (m_client_msg)
	{
		m_client_msg.reset();
	}
	m_control_mutex.unlock();
}


bool ClientComm::sendMsg(const std::string &msg) const
{
	try
	{
		boost::system::error_code ec;
		return boost::asio::write(*m_client, boost::asio::buffer(msg), ec);
	}
	catch (boost::system::system_error &e)
	{
		std::cout << "[ClientComm] Failed to send message: " << e.what() << std::endl;
		return false;
	}
}