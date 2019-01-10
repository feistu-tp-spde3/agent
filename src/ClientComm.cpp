#include <boost/chrono.hpp>

#include "ClientComm.hpp"
#include "Configuration.hpp"


ClientComm::ClientComm(Configuration &config, std::mutex &control_mutex) :
	m_config{ config },
	m_control_mutex{ control_mutex },
	m_client_msg{ "" },
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
		boost::asio::ip::udp::socket listener(*m_io_service, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), listener_port));
		boost::asio::ip::udp::endpoint sender_endpoint;

		listener.set_option(boost::asio::socket_base::broadcast(true));

		int senderPort = -1;
		char buffer[MAX_BUFFER_SIZE] = { 0 };
		size_t bytesReceived = 0;
		bool messageReceived = false;

		m_control_mutex.lock();
		m_listener_ready = false;
		m_control_mutex.unlock();

		while (!messageReceived)
		{
			try
			{
				bytesReceived = listener.receive_from(boost::asio::buffer(buffer, MAX_BUFFER_SIZE), sender_endpoint);
			}
			catch (std::exception &e)
			{
				std::cout << "[ClientComm] Exception: " << e.what() << std::endl;
			}

			if (bytesReceived)
			{
				std::string message(buffer, bytesReceived);
				std::cout << "[ClientComm] Message received: \"" << message << "\"\n";

				if (message.find("agentSearch", 0) != std::string::npos)
				{
					messageReceived = true;
					listener.close();

					// vyparsovanie portu zo spravy
					senderPort = atoi(message.substr(message.find("/", 0) + 1, message.size() - message.find("/", 0)).c_str());
				}
			}

			boost::this_thread::sleep_for(boost::chrono::milliseconds(100));
		}

		if (messageReceived && senderPort != -1)
		{
			if (!connect(sender_endpoint.address(), senderPort))
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
	std::cout << "[ClientComm] Establishing connection" << std::endl;
	boost::this_thread::sleep_for(boost::chrono::milliseconds(CONNECT_TIMEOUT));

	boost::asio::ip::tcp::endpoint endpoint(ip, port);

	m_client.reset();
	m_client = std::make_shared<boost::asio::ip::tcp::socket>(*m_io_service);

	try
	{
		m_client->connect(endpoint);
	}
	catch (std::exception &e)
	{
		std::cout << "[ClientComm] Failed to establish TCP connection to client: " << e.what() << "\n";
		return false;
	}

	// odoslanie prvej spravy, ktorou sa identifikuje agent
	boost::system::error_code error;

	const std::string msg = m_config.getAgentName();
	size_t bytesSent = boost::asio::write(*m_client, boost::asio::buffer(msg), error);
	std::cout << "[ClientComm] Sent identification message(" << bytesSent << "B): " << msg << "\n";

	// ak sa podarilo spojit tak spustime vlakno na prijmanie sprav
	if (m_client->is_open())
	{
		boost::thread t = boost::thread([this]()
		{
			char buffer[MAX_BUFFER_SIZE] = { 0 };
			boost::system::error_code ec;

			while (true)
			{
				try
				{
					size_t received = m_client->read_some(boost::asio::buffer(buffer, MAX_BUFFER_SIZE), ec);
					if (ec == boost::asio::error::eof)
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
						std::string message(buffer, received);
						std::cout << "[ClientComm] Message received: " << message << std::endl;
						m_client_msg = message;
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
	}

	return true;
}


bool ClientComm::isListenerReady() const
{
	return m_listener_ready;
}


void ClientComm::ack()
{
	m_control_mutex.lock();
	m_client_msg = "";
	m_control_mutex.unlock();
}


bool ClientComm::sendMsg(const std::string &msg) const
{
	boost::system::error_code ec;

	try
	{
		size_t n_sent = boost::asio::write(*m_client, boost::asio::buffer(msg), ec);
		if (ec == boost::asio::error::eof)
		{
			return false;
		}

		return n_sent;
	}
	catch (boost::system::system_error &e)
	{
		std::cout << "[ClientComm] Failed to send message: " << e.what() << std::endl;
		return false;
	}
}