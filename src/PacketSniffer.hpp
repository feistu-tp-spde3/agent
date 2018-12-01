#pragma once


#include "Configuration.hpp"

class PacketSniffer
{
public:
	bool init(const Configuration &config);
	void run(const Configuration &config);
};