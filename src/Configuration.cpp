#include "Configuration.hpp"
#include "pugixml.hpp"


#include <boost/filesystem/path.hpp>
#include <boost/filesystem.hpp>
#include <boost/asio.hpp>

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
    createFilter();
    createDirectory();
}


void Configuration::parse()
{
    boost::filesystem::path path(boost::filesystem::current_path());
    
    std::string fullPath = path.string() + "/" + m_filename;
    pugi::xml_document configurationFile;
    pugi::xml_parse_result result = configurationFile.load_file(fullPath.c_str());

	if (result.status != pugi::xml_parse_status::status_ok)
	{
		std::cout << "[Configuration] Could not parse configuration file: " << result.description() << std::endl;
		return;
	}

    pugi::xml_node configuration = configurationFile.child("Configuration");
    pugi::xml_node agent;
        
    if(configuration)
        agent = configuration.child("Agent");

    // nacitanie nastaveni agenta
    if (agent)
    {
        if (agent.child("Name"))
            mAgentName = agent.child("Name").text().as_string();

        if (agent.child("IP_Protocol"))
            mIPProtocol = agent.child("IP_Protocol").text().as_string();

        if (agent.child("SrcAddr"))
            mSrcAddr = agent.child("SrcAddr").text().as_string();

        if (agent.child("DstAddr"))
            mDstAddr = agent.child("DstAddr").text().as_string();

        if (agent.child("CoreProtocol"))
            mCoreProtocol = agent.child("CoreProtocol").text().as_string();

        if (agent.child("SrcPort"))
            mSrcPort = agent.child("SrcPort").text().as_string();

        if (agent.child("DstPort"))
            mDstPort = agent.child("DstPort").text().as_string();

        if (agent.child("Bound"))
            mBound = agent.child("Bound").text().as_string();

        if (agent.child("QueueLength"))
            mQueueLength = agent.child("QueueLength").text().as_uint();

        if (agent.child("QueueTime"))
            mQueueTime = agent.child("QueueTime").text().as_uint();

        if (agent.child("Directory"))
            mDirectory = agent.child("Directory").text().as_string();
    }

    // nacitanie kolektorov
    pugi::xml_node sender = configuration.child("Sender");

    if (sender)
    {
        for (pugi::xml_node collector = sender.child("Collector"); collector; collector = collector.next_sibling("Collector"))
        {
            std::string collectorAddr = collector.text().as_string();
            std::string addr = collectorAddr.substr(0, collectorAddr.find(":", 0));
            std::string port = collectorAddr.substr(collectorAddr.find(":", 0) + 1, collectorAddr.length() - collectorAddr.find(":", 0));
        
            Collector newCollector(addr, port);
            m_collectors.push_back(newCollector);
        }

        if (sender.child("SendingTime"))
        {
            mSendingTime = atoi(sender.child("SendingTime").text().as_string());
        }
    }
}


void Configuration::createFilter()
{
    if (!mBound.empty())
    {
        mFilter += mBound;
    }
		
    if (!mIPProtocol.empty())
    {
        if (mIPProtocol == "IPv4")
        {
            mFilter += " and ip";
        }

        if (mIPProtocol == "IPv6")
        {
            mFilter += " and ipv6";
        }
    }

    if (!mSrcAddr.empty())
    {
        mFilter += " and ip.SrcAddr == " + mSrcAddr;
    }
		
    if (!mDstAddr.empty())
    {
        mFilter += " and ip.DstAddr == " + mDstAddr;
    }
		
    if (!mCoreProtocol.empty())
    {
        if (mCoreProtocol == "TCP")
        {
            if (!mSrcPort.empty())
            {
                mFilter += "and tcp.SrcPort == " + mSrcPort;
            }
                                
            if (!mDstPort.empty())
            {
                mFilter += "and tcp.DstPort == " + mDstPort;
            }
        }
        else if (mCoreProtocol == "UDP")
        {
            if (!mSrcPort.empty())
            {
                mFilter += "and udp.SrcPort == " + mSrcPort;
            }
                                
            if (!mDstPort.empty())
            {
                mFilter += "and udp.DstPort == " + mDstPort;
            }	
        } 
        else if (mCoreProtocol == "ICMP")
        {
                mFilter += " and icmp";
        }
    }

    // v pripade ak sme nemali nastaveny konfiguracny subor filtrujeme celu prevadzku
    if (mFilter.empty())
    {
        std::string ip = getLocalIP();
        mFilter = "ip.SrcAddr == " + ip + " or ip.DstAddr == " + ip;
    }

    std::cout << "[Configuration] Filter created from configuration file: " << mFilter << std::endl;
}


std::string Configuration::getLocalIP() const
{
    return "localhost";
}


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
