#include "Agent.hpp"


int main(int argc, char **argv)
{
/*
    Configuration config("config_agent.xml");
    std::shared_ptr<PacketSniffer> sniffer;


    UdpListener listener(config);
    listener.run();

    sniffer->init(config);
    sniffer->run(config);
*/
    Agent agent("config_agent.xml");

    return 0;
}
