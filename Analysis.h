#pragma once
#include <vector>
#include <string>
#include <utility>
#include <cstdint>

// Simple packet representation
struct Packet {
    std::string srcIP;
    std::string dstIP;
    uint16_t srcPort;
    uint16_t dstPort;
    std::string protocol;
    uint32_t length;
    std::vector<uint8_t> rawData;
};

// Metrics snapshot
struct Metrics {
    uint64_t totalPackets;
    uint64_t totalBytes;
    double bps;
    double pps;
    double lastLatency;
    double jitter;
};

// --- Core API ---
void ProcessPacket(const Packet& pkt);
void UpdateMetrics(double dt);

std::vector<Packet> GetRecentPackets(size_t maxCount);
Metrics GetMetrics();
std::vector<float> GetBpsHistory();
std::vector<float> GetPpsHistory();
std::tuple<float, float, float, float> GetProtocolCounts();

// --- Per-host analytics ---
std::vector<std::pair<std::string, float>> GetTopHosts(size_t maxHosts);