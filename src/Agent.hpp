#pragma once

#include <memory>

#include "Configuration.hpp"
#include "PacketSniffer.hpp"
#include "ClientComm.hpp"

#ifdef _WIN32
#include "Windivert.hpp"
#elif __linux__
#include "LinuxPacketSniffer.hpp"
#else
#error "Operating system not supported"
#endif


class Agent
{
private:
    std::mutex m_control_mutex;

    Configuration m_config;
    std::shared_ptr<PacketSniffer> m_sniffer;

    ClientComm m_client_comm;

public:
    Agent(const std::string &config_filename);
};
