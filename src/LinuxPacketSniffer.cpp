#include "LinuxPacketSniffer.hpp"


#include <iostream>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <libnetfilter_queue/libnetfilter_queue.h>


bool LinuxPacketSniffer::init(const Configuration& config)
{
    return true;
}

void LinuxPacketSniffer::run(const Configuration& config)
{
    std::cout << "LinuxPacketSniffer\n";
}
