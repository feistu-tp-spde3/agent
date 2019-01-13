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
	m_filename = filename;
	std::cout << "[Configuration] Creating configuration from file \"" << filename << "\"\n";

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
		for (const pugi::xml_node &node : sender.children("Collector"))
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


bool Configuration::addMonitoredProcess(const std::string &procname)
{
	// It could have been a set.. but NO
	for (const std::string &p : m_monitored_processes)
	{
		if (p == procname)
		{
			return false;
		}
	}

	m_monitored_processes.push_back(procname);

	// The config is guaranteed to have <Agent> inside <Configuration> node, if this fails, it's bad
	pugi::xml_node agent = m_xml.child("Configuration").child("Agent");

	pugi::xml_node monitored = agent.child("MonitoredProcesses");
	if (!monitored)
	{
		monitored = agent.append_child("MonitoredProcesses");
	}

	pugi::xml_node proc = monitored.append_child("Process");
	proc.append_child(pugi::node_pcdata).set_value(procname.c_str());

	return saveConfig();
}


bool Configuration::removeMonitoredProcess(const std::string &procname)
{
	bool found = false;
	std::vector<std::string>::iterator it = m_monitored_processes.begin();
	while (it != m_monitored_processes.end())
	{
		if (procname == *it)
		{
			it = m_monitored_processes.erase(it);
			found = true;
		}
		else
		{
			++it;
		}
	}

	if (!found)
	{
		return false;
	}

	pugi::xml_node agent = m_xml.child("Configuration").child("Agent");
	pugi::xml_node monitored = agent.child("MonitoredProcesses");
	if (!monitored)
	{
		return false;
	}

	std::vector<pugi::xml_node> nodes_to_remove;

	// Removing while iterating doesn't work even with ::iterator and stuff like that..
	for (pugi::xml_node node : monitored.children("Process"))
	{
		const std::string &value = node.text().as_string();
		if (procname == value)
		{
			nodes_to_remove.push_back(node);
		}
	}

	for (pugi::xml_node node : nodes_to_remove)
	{
		monitored.remove_child(node);
	}

	return saveConfig();
}


bool Configuration::saveConfig()
{
	return m_xml.save_file(m_filename.c_str());
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