#pragma once

#include <string>
#include <iostream>
#include <mutex>
#include <vector>

#include "Collector.hpp"


class Configuration
{
private:
	std::mutex &m_control_mutex;
	const std::string &m_filename;

	std::vector<Collector> m_collectors;

	// nazov agenta
	std::string mAgentName;

	// filtrovanie podla IP protokolu(IPv4, IPv6)
	std::string mIPProtocol;

	// filtrovanie podla zdrojovej adresy
	std::string mSrcAddr;

	// filtrovanie podla cielovej adresy
	std::string mDstAddr;

	// filtrovanie podla vnoreneho protokolu(TCP,UDP,...)
	std::string mCoreProtocol;

	// filtrovanie podla zdrojoveho portu
	std::string mSrcPort;

	// filtrovanie podla cieloveho portu
	std::string mDstPort;

	// filtrovanie prichadzajucich/odchadzajucich paketov
	std::string mBound;

	// velkost fronty na pakety
	unsigned mQueueLength{ 8192 };

	// maximalny cas paketu vo fronte
	unsigned mQueueTime{ 2048 };

	// cas po ktorom sa odosielaju data na kolektor
	unsigned mSendingTime{ 60 };

	// adresar kam sa ukladaju pakety
	std::string mDirectory{ "Data/" };

	// filter pre packet sniffer
	std::string mFilter;

	// parsovanie xml dokumentu
	void parse();

	// vytvorenie filtra
	void createFilter();

	// vytvorenie adresara na ukladanie paketov
	void createDirectory();

	// ziskanie lokalnej ipcky
	std::string getLocalIP() const;

public:
	Configuration(const std::string &filename, std::mutex &control_mutex);

	const std::vector<Collector> &getCollectors() { return m_collectors; }
	std::string getFilter() const { return mFilter; }

	unsigned getQueueLenght() const { return mQueueLength; }
	unsigned getQueueTime() const { return mQueueTime; }
	unsigned getSendingTime() const { return mSendingTime; }

	std::string getDirectory() const { return mDirectory; }
	std::string getAgentName() const { return mAgentName; }
};
