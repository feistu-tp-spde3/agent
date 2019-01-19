#include "ProcessDiscovery.hpp"

#ifdef _WIN32

#include <windows.h>
#include <tlhelp32.h>


bool ProcessDiscovery::isProcessRunning(const std::string &processName)
{
	std::wstring processNameW(processName.begin(), processName.end());
	bool exists = false;
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry))
	{
		while (Process32Next(snapshot, &entry))
		{
			std::string exeFile(entry.szExeFile);
			std::wstring exeFileW(exeFile.begin(), exeFile.end());

			if (exeFileW == processNameW)
			{
				exists = true;
				break;
			}
		}
	}

	CloseHandle(snapshot);
	return exists;
}

#elif __linux__

#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>


pid_t ProcessDiscovery::getProcessPidByName(const std::string &procName)
{
	pid_t pid = -1;

	// Open the /proc directory
	DIR *dp = opendir("/proc");
	if (dp == nullptr)
	{
		return pid;
	}

	// Enumerate all entries in directory until process found
	struct dirent *dirp;
	while (pid < 0 && (dirp = readdir(dp)))
	{
		// Skip non-numeric entries
		const char *name = dirp->d_name;
		if (name[0] < '0' || name[0] > '9')
		{
			continue;
		}

		int id = std::stoi(name);
		if (id > 0)
		{
			// Read contents of virtual /proc/{pid}/cmdline file
			std::string cmdPath = "/proc/" + std::string(name) + "/cmdline";
			std::ifstream cmdFile(cmdPath);
			std::string cmdLine;
			getline(cmdFile, cmdLine);

			if (!cmdLine.empty())
			{
				// Keep first cmdline item which contains the program path
				size_t pos = cmdLine.find('\0');
				if (pos != std::string::npos)
					cmdLine = cmdLine.substr(0, pos);
				// Keep program name only, removing the path
				pos = cmdLine.rfind('/');
				if (pos != std::string::npos)
					cmdLine = cmdLine.substr(pos + 1);
				// Compare against requested process name
				if (procName == cmdLine)
					pid = id;
			}
		}
	}

	closedir(dp);

	return pid;
}


bool ProcessDiscovery::isProcessRunning(const std::string &processName)
{
	pid_t pid = getProcessPidByName(processName);
	if ((pid != -1) && (kill(pid, 0) == 0))
	{
		return true;
	}

	return false;
}

#endif