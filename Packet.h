#pragma once
#include <string>
#include <vector>
#include <pcap.h>

struct Packet {
    timeval ts{};
    std::string srcIP;
    std::string dstIP;
    uint16_t srcPort;
    uint16_t dstPort;
    std::string protocol;
    uint32_t length;
    std::vector<uint8_t> rawData;
};
