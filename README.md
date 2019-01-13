# agent

## New features
- Windows & Linux support, same source code
- Npcap (https://nmap.org/npcap/) library used for consistent filter syntax (https://linux.die.net/man/7/pcap-filter)
- Packets are now sent from memory, not through file write & Java process spawn
- Two-way communication with monitor (previously: monitor -> agent)
- Communication format is JSON (previously: basic text)
- Respawn monitor listener on monitor disconnect (previously: only one monitor could've connected in the lifetime of the agent)
- Monitor running processes (defined in xml config)
- Monitored processes can be added, deleted on-demand & saved to config

monitor -> agent:
```
{
    "cmd": <ping|filter|proc|..>",
    "action: <get|set|..>",
    "data": ..
}
```

agent -> monitor:
```
{
    "response": ...    
}
```

## Build

### Windows

1. MSVC 2017 (v141)  
2. Download "boost_1_68_0-msvc-14.1-32.exe" from https://sourceforge.net/projects/boost/files/boost-binaries/1.68.0/
3. Download "Latest Npcap release self-installer" from https://nmap.org/download.html (when installing, select Winpcap compat mode)
4. Download NPCAP SDK https://nmap.org/npcap/dist/npcap-sdk-1.01.zip
5. Add environment variables `BOOST_INCLUDE_PATH`, `BOOST_LIB_PATH`, `NPCAP_INCLUDE_PATH`, `NPCAP_LIB_PATH`, sample values:
```
BOOST_INCLUDE_PATH=C:\boost_1_68_0_32
BOOST_LIB_PATH=C:\boost_1_68_0_32\lib32-msvc-14.1
NPCAP_INCLUDE_PATH=C:\npcap\Include
NPCAP_LIB_PATH=C:\npcap\Lib
```

### Linux

1. sudo apt-get install automake libpcap-dev build-essential
2. Install boost your preferred way 

If you compiled Boost yourself, change this path in `CMakeLists.txt`:
```
set (BOOST_ROOT "/home/user/boost_1_68_0")
```

If you didn't compile Boost yourself, change this line to FALSE:
```
# Set to TRUE if you custom-compiled Boost and then change BOOST_ROOT
set (Boost_NO_SYSTEM_PATHS TRUE)
```

```
cmake .
make
```
