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
    
    std::shared_ptr<boost::asio::ip::tcp::socket> m_client;
    std::string m_client_msg;

    void receiveMessage();

    const size_t MAX_BUFFER_SIZE{ 1024 };
    const unsigned int CONNECT_TIMEOUT{ 1000 };

public:
    ClientComm(Configuration &config, std::mutex &control_mutex);

    // Creates a UDP server on <listener_port> and waits for 1 client
    void waitForClient(uint16_t listener_port);

    void connect(const boost::asio::ip::address &ip, uint16_t port);

    const std::string &getMsg() const { return m_client_msg; }
};
