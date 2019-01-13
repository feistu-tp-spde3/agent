#include "Agent.hpp"


int main()
{
	Agent agent;

	if (!agent.createConfiguration("config_agent.xml"))
	{
		return EXIT_FAILURE;
	}

	if (!agent.spawnSniffer())
	{
		return EXIT_FAILURE;
	}

	agent.spawnCommServer(8888);
	agent.run();

	return EXIT_SUCCESS;
}
