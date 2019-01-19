#pragma once

#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <iostream>
#include <exception>
#include <mutex>
#include <memory>


class Configuration;


class ClientComm
{
private:
	std::mutex &m_control_mutex;
	Configuration &m_config;

	boost::thread m_listener_thread;
	bool m_listener_ready{ true };

	std::shared_ptr<boost::asio::io_service> m_io_service;
	std::shared_ptr<boost::asio::ip::tcp::socket> m_client;
	std::shared_ptr<std::string> m_client_msg;

	// Size of receiving buffer
	static const size_t MAX_BUFFER_SIZE{ 1024 };

	// Wait this many miliseconds before initiating connection after handshake
	static const unsigned int CONNECT_WAIT{ 1000 };

public:
	ClientComm(Configuration &config, std::mutex &control_mutex);

	// Creates an UDP server on <listener_port> and waits for max 1 connection at once, then
	// shuts down
	// Connection is initiated only when identification handshake is made
	// Respawn of the UDP server is done through Agent class
	void waitForClient(uint16_t listener_port);
	
	// Initiates TCP connection with host after handshake
	// Port is transmitted by the one that initiates handshake (agentSearch/<port> msg)
	bool connect(const boost::asio::ip::address &ip, uint16_t port);

	// Acknowledge received message by deleting the previous one
	void ack();

	bool sendMsg(const std::string &msg) const;

	const std::shared_ptr<std::string> &getMsg() const { return m_client_msg; }
	std::shared_ptr<boost::asio::io_service> getIoService() const { return m_io_service; }
	bool isListenerReady() const { return m_listener_ready; }
};
