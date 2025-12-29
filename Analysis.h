#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

// ---------------- Packet ----------------
struct Packet
{
    std::string srcIP;
    std::string dstIP;
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    uint8_t  protocolId = 0;   // IPPROTO_TCP / UDP / ICMP
    std::string protocol;      // "TCP", "UDP", "ICMP"
    uint32_t length = 0;
    bool isOutbound = true;
	std::vector<uint8_t> rawData;
};

// ---------------- Metrics ----------------
struct Metrics
{
    uint64_t totalPackets = 0;
    uint64_t totalBytes = 0;
    double   bps = 0.0;
    double   pps = 0.0;
    double   totalMB = 0.0;
    double   lastLatency = 0.0;
    double   jitter = 0.0;
};

// ---------------- Flow ----------------
struct FlowKey
{
    std::string srcIP;
    std::string dstIP;
    uint16_t srcPort;
    uint16_t dstPort;
    uint8_t  protocol;
};

struct FlowStats
{
    uint64_t bytesUp = 0;
    uint64_t bytesDown = 0;
    uint64_t packetsUp = 0;
    uint64_t packetsDown = 0;
    double firstSeen = 0.0;
    double lastSeen = 0.0;
};

struct Flow
{
    FlowKey key;
    FlowStats stats;
};

// ---------------- Analysis API ----------------
void ProcessPacket(const Packet& pkt);
void UpdateMetrics(double dt);

// GUI queries
Metrics GetMetrics();
std::vector<float> GetBpsHistory();
std::vector<float> GetPpsHistory();
std::vector<Packet> GetRecentPackets(size_t maxCount);

// Flow queries
std::vector<Flow> GetTopFlows(size_t maxFlows);
std::vector<std::pair<std::string, float>> GetTopHosts(size_t maxHosts);
