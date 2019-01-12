#include "Agent.hpp"


int main()
{
	Agent agent;

	if (!agent.createConfiguration("config_agent.xml"))
	{
		return -1;
	}

	if (!agent.spawnSniffer())
	{
		return -1;
	}

	agent.spawnCommServer(8888);
	agent.run();

	return 0;
}
