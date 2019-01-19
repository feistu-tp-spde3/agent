#pragma once

#include <string>


class ProcessDiscovery
{
private:
#ifdef __linux__
	pid_t getProcessPidByName(const std::string &procName);
#endif
public:
	bool isProcessRunning(const std::string &processName);
};