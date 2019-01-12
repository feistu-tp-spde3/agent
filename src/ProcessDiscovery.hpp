#pragma once

#include <string>

class ProcessDiscovery
{
private:
#ifdef __linux__
	pid_t GetProcessPidByName(std::string procName);
#endif
public:
	bool IsProcessRunning(std::string processName);
};