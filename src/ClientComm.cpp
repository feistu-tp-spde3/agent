#include "ClientComm.hpp"
#include "Configuration.hpp"

#include <boost/chrono.hpp>
#include "json.hpp"


ClientComm::ClientComm(Configuration &config, std::mutex &control_mutex) :
    m_config{ config },
    m_control_mutex{ control_mutex },
    m_client_msg{ "" }
{
    ;
}


void ClientComm::waitForClient(uint16_t listener_port)
{
    m_listener_thread = boost::thread([this, listener_port]() 
    {
        std::cout << "[ClientComm] Launching communication thread on port " << listener_port << std::endl;

        boost::asio::io_service io_service;
        boost::system::error_code error;
        boost::asio::ip::udp::socket listener(io_service, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), listener_port));
        boost::asio::ip::udp::endpoint sender_endpoint;

        listener.set_option(boost::asio::socket_base::broadcast(true));

        int senderPort = -1;
		char buffer[MAX_BUFFER_SIZE] = {0};
        size_t bytesReceived = 0;
        bool messageReceived = false;

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
                std::cout << "[ClientComm] Message received: " << message << std::endl;

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
            //client_connection = std::make_unique<TCPConnection>();
            //client_connection->establishConnection(senderEndpoint.address(), senderPort, m_config);
            this->connect(sender_endpoint.address(), senderPort);
        }
    });

    m_listener_thread.detach();
}


void ClientComm::connect(const boost::asio::ip::address &ip, uint16_t port)
{
    std::cout << "[ClientComm] Establishing connection" << std::endl;
    boost::this_thread::sleep_for(boost::chrono::milliseconds(CONNECT_TIMEOUT));


    boost::asio::io_service io;
    boost::asio::ip::tcp::endpoint endpoint(ip, port);
    m_client = std::make_shared<boost::asio::ip::tcp::socket>(io);

    try 
    {
        m_client->connect(endpoint);
    }
    catch (std::exception &e)
    {
        std::cout << "[ClientComm] Failed to establish TCP connection to client: " << e.what() << std::endl;
        return;
    }

    // odoslanie prvej spravy, ktorou sa identifikuje agent
    boost::system::error_code error;
    
    const std::string msg = m_config.getAgentName() + "\n";
    std::size_t bytesSent = boost::asio::write(*m_client, boost::asio::buffer(msg), error);
    std::cout << "[ClientComm] Sent identification message(" << bytesSent << "B): " << msg;

    // ak sa podarilo spojit tak spustime vlakno na prijmanie sprav
    if (m_client->is_open())
    {
        boost::thread t = boost::thread([this]() 
        {
            while (true)
            {
                this->receiveMessage();
            }
        });

        t.detach();
    }
}


void ClientComm::receiveMessage()
{
    boost::system::error_code error;
    char buffer[MAX_BUFFER_SIZE] = {0};
    std::size_t bytesReceived = 0;
	
    while (bytesReceived == 0)
    {
        bytesReceived = m_client->read_some(boost::asio::buffer(buffer, MAX_BUFFER_SIZE), error);

        if (bytesReceived != 0)
        {
            m_control_mutex.lock();
            std::string message(buffer, bytesReceived);
            std::cout << "[ClientComm] Message received: " << message << std::endl;
            m_client_msg = message;
            m_control_mutex.unlock();
        }
    }
}
