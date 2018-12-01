#pragma once

#include "Configuration.hpp"

class PacketSniffer
{
public:
    virtual bool init(const Configuration &config) = 0;
    virtual void run(const Configuration &config) = 0;
    virtual ~PacketSniffer() {};
    //virtual bool init(const std::string &filter, const Configuration &config) = 0;
};