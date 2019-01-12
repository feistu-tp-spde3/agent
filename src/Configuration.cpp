#include <boost/filesystem/path.hpp>
#include <boost/filesystem.hpp>
#include <boost/asio.hpp>

#include "Configuration.hpp"


#ifdef WIN32
#include <direct.h>
#include <Windows.h>
#elif __linux__
#include <unistd.h>
#include <netdb.h>
#endif


Configuration::Configuration()
{
	;
}


bool Configuration::parse(const std::string &filename)
{
	std::cout << "[Configuration] Creating configuration\n";

	boost::filesystem::path path(boost::filesystem::current_path());

	std::string fullpath = path.string() + "/" + filename;
	pugi::xml_parse_result result = m_xml.load_file(fullpath.c_str());

	if (result.status != pugi::xml_parse_status::status_ok)
	{
		std::cerr << "[Configuration] Could not parse configuration file: " << result.description() << "\n";
		return false;
	}

	pugi::xml_node configuration = m_xml.child("Configuration");
	if (!configuration)
	{
		std::cerr << "[Configuration] Invalid config: no Configuration node\n";
		return false;
	}

	pugi::xml_node agent = configuration.child("Agent");
	if (!agent)
	{
		std::cerr << "[Configuration] Invalid config: no Agent node in Configuration\n";
		return false;
	}

	pugi::xml_node agent_name = agent.child("Name");
	if (!agent_name)
	{
		std::cerr << "[Configuration] Invalid config: the agent needs a name\n";
		return false;
	}

	if (agent_name.text().empty())
	{
		std::cerr << "[Configuration] Invalid config: agent name cannot be empty\n";
		return false;
	}

	m_agent_name = agent_name.text().as_string();

	// Don't care if it's empty
	if (agent.child("Filter"))
	{
		m_agent_filter = agent.child("Filter").text().as_string();
	}

	pugi::xml_node monitored_procs = agent.child("MonitoredProcesses");
	for (pugi::xml_node proc : monitored_procs.children("Process"))
	{
		if (proc.text().empty())
		{
			continue;
		}

		std::string name = proc.text().as_string();
		m_monitored_processes.push_back(name);
	}

	pugi::xml_node sender = configuration.child("Sender");
	if (sender)
	{
		for (pugi::xml_node node : sender.children("Collector"))
		{
			std::string host = node.text().as_string();
			size_t delim = host.find(":", 0);
			if (delim == std::string::npos)
			{
				std::cerr << "[Configuration] Bad collector format, ignoring\n";
				continue;
			}

			std::string addr = host.substr(0, delim);
			std::string port = host.substr(delim + 1, host.length() - delim);

			Collector collector(addr, port);
			m_collectors.push_back(collector);
		}

		if (sender.child("Interval"))
		{
			m_send_interval = sender.child("Interval").text().as_uint();
		}
	}

	return true;
}


/*
void Configuration::createDirectory()
{
	boost::filesystem::path current_directory(boost::filesystem::current_path());
	boost::filesystem::path data_path = current_directory / boost::filesystem::path(mDirectory);

	if (!boost::filesystem::exists(data_path))
	{
		boost::filesystem::create_directory(data_path);
	}
	else
	{
		std::cout << "[Configuration] Directory " << data_path << " already exists!" << std::endl;
	}
}
*/