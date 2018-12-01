#pragma once

#include <string>
#include <iostream>
#include <mutex>


class Configuration 
{
private:
    std::mutex &m_control_mutex;
    const std::string &m_filename;

    std::string mAgentName;	    // nazov agenta
    std::string mIPProtocol;	    // filtrovanie podla IP protokolu(IPv4, IPv6)
    std::string mSrcAddr;	    // filtrovanie podla zdrojovej adresy
    std::string mDstAddr;	    // filtrovanie podla cielovej adresy
    std::string mCoreProtocol;	    // filtrovanie podla vnoreneho protokolu(TCP,UDP,...)
    std::string mSrcPort;	    // filtrovanie podla zdrojoveho portu
    std::string mDstPort;	    // filtrovanie podla cieloveho portu
    std::string mBound;		    // filtrovanie prichadzajucich/odchadzajucich paketov

    unsigned mQueueLength{ 8192 };	    // velkost fronty na pakety
    unsigned mQueueTime{ 2048 };	    // maximalny cas paketu vo fronte
    unsigned mSendingTime{ 60 };	    // cas po ktorom sa odosielaju data na kolektor

    std::string mDirectory{ "Data/" };	    // adresar kam sa ukladaju pakety

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

    std::string getFilter() const { return mFilter; }

    unsigned getQueueLenght() const { return mQueueLength; }
    unsigned getQueueTime() const { return mQueueTime; }
    unsigned getSendingTime() const { return mSendingTime; }

    std::string getDirectory() const { return mDirectory; }
    std::string getAgentName() const { return mAgentName; }
};
