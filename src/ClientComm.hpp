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

	// size of receiving buffer from client
	static const size_t MAX_BUFFER_SIZE{ 1024 };

	// in miliseconds
	static const unsigned int CONNECT_TIMEOUT{ 1000 };

public:
	ClientComm(Configuration &config, std::mutex &control_mutex);

	// Creates a UDP server on <listener_port> and waits for max 1 client at once
	void waitForClient(uint16_t listener_port);

	bool connect(const boost::asio::ip::address &ip, uint16_t port);
	
	bool isListenerReady() const;

	// Acknowledge received message by deleting the previous one
	void ack();

	bool sendMsg(const std::string &msg) const;

	const std::shared_ptr<std::string> &getMsg() const { return m_client_msg; }
	std::shared_ptr<boost::asio::io_service> getIoService() const { return m_io_service; }
};
