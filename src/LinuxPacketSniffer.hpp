#pragma once


#include "PacketSniffer.hpp"


class LinuxPacketSniffer : public PacketSniffer
{
private:


public:
    bool init(const Configuration &config) override;
    void run(const Configuration &config) override;

};
