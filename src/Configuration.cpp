#include <boost/filesystem/path.hpp>
#include <boost/filesystem.hpp>
#include <boost/asio.hpp>

#include "Configuration.hpp"
#include "pugixml.hpp"

#ifdef WIN32
#include <direct.h>
#include <Windows.h>
#elif __linux__
#include <unistd.h>
#include <netdb.h>
#endif


Configuration::Configuration(const std::string &filename, std::mutex &control_mutex) :
	m_filename{ filename },
	m_control_mutex{ control_mutex }
{
	std::cout << "[Configuration] Creating configuration" << std::endl;
	parse();
}


bool Configuration::parse()
{
	boost::filesystem::path path(boost::filesystem::current_path());

	std::string fullpath = path.string() + "/" + m_filename;
	pugi::xml_document xml;
	pugi::xml_parse_result result = xml.load_file(fullpath.c_str());

	if (result.status != pugi::xml_parse_status::status_ok)
	{
		std::cerr << "[Configuration] Could not parse configuration file: " << result.description() << "\n";
		return false;
	}

	pugi::xml_node configuration = xml.child("Configuration");
	pugi::xml_node agent;

	if (configuration)
	{
		agent = configuration.child("Agent");
	}

	// nacitanie nastaveni agenta
	if (agent)
	{
		if (agent.child("Name"))
		{
			m_agent_name = agent.child("Name").text().as_string();
		}

		if (agent.child("Filter"))
		{
			m_agent_filter = agent.child("Filter").text().as_string();
		}
	}

	// nacitanie kolektorov
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