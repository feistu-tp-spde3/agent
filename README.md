# agent

## New features
- Windows & Linux support, same source code
- Npcap (https://nmap.org/npcap/) library used for consistent filter syntax (https://linux.die.net/man/7/pcap-filter)
- Packets are now sent from memory, not through file write & Java process spawn
- Two-way communication with monitor
- Respawn monitor listener on monitor disconnect (previously only one monitor could've connected in the lifetime of an agent)
- (TODO) Monitor running processes (defined in config)

## Build

### Windows

1. MSVC 2017 (v141)  
2. Download "boost_1_68_0-msvc-14.1-32.exe" from https://sourceforge.net/projects/boost/files/boost-binaries/1.68.0/
3. Download "Latest Npcap release self-installer" from https://nmap.org/download.html (when installing, select Winpcap compat mode)
4. Download NPCAP SDK https://nmap.org/npcap/dist/npcap-sdk-1.01.zip
5. Add environment variables BOOST_INCLUDE_PATH, BOOST_LIB_PATH, NPCAP_INCLUDE_PATH, NPCAP_LIB_PATH

### Linux

1. apt-get install automake
2. apt-get install libpcap-dev
3. TBC
