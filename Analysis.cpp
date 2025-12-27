#include "Analysis.h"
#include <mutex>
#include <deque>
#include <atomic>
#include <vector>
#include <map>
#include <string>
#include <tuple>
#include <algorithm>
#include <cmath>

// Mutex for thread safety
static std::mutex g_mutex;

// Packet storage
static std::deque<Packet> g_packets;
constexpr size_t MAX_HISTORY = 50000;

// Metrics
static std::atomic<uint64_t> g_totalBytes{0};
static std::atomic<uint64_t> g_totalPackets{0};
static std::deque<float> g_bpsHistory(300, 0.0f);
static std::deque<float> g_ppsHistory(300, 0.0f);

// Per-host traffic
struct HostTraffic {
    uint64_t bytesIn = 0;
    uint64_t bytesOut = 0;
};
static std::map<std::string, HostTraffic> g_hostTraffic;

// --- Packet processing ---
void ProcessPacket(const Packet& pkt)
{
    std::lock_guard<std::mutex> lock(g_mutex);

    g_packets.push_back(pkt);
    g_totalBytes += pkt.length;
    g_totalPackets++;

    // Per-host traffic
    g_hostTraffic[pkt.srcIP].bytesOut += pkt.length;
    g_hostTraffic[pkt.dstIP].bytesIn += pkt.length;

    if (g_packets.size() > MAX_HISTORY)
        g_packets.pop_front();
}

// --- Metrics update ---
void UpdateMetrics(double dt)
{
    std::lock_guard<std::mutex> lock(g_mutex);

    if (g_bpsHistory.size() >= 300) {
        g_bpsHistory.pop_front();
        g_ppsHistory.pop_front();
    }

    static uint64_t lastBytes = 0;
    static uint64_t lastPackets = 0;

    uint64_t bytes = g_totalBytes.load();
    uint64_t packets = g_totalPackets.load();

    double bps = double(bytes - lastBytes) / dt;
    double pps = double(packets - lastPackets) / dt;

    lastBytes = bytes;
    lastPackets = packets;

    g_bpsHistory.push_back((float)bps);
    g_ppsHistory.push_back((float)pps);
}

// --- Recent packets ---
std::vector<Packet> GetRecentPackets(size_t maxCount)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    std::vector<Packet> copy;
    if (g_packets.size() > maxCount)
        copy.insert(copy.end(), g_packets.end() - maxCount, g_packets.end());
    else
        copy.assign(g_packets.begin(), g_packets.end());
    return copy;
}

std::pair<double, double> GetBandwidthAndPps()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_bpsHistory.empty() || g_ppsHistory.empty())
        return { 0.0, 0.0 };
    return { g_bpsHistory.back(), g_ppsHistory.back() };
}

// --- BPS/PPS history ---
std::vector<float> GetBpsHistory()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return std::vector<float>(g_bpsHistory.begin(), g_bpsHistory.end());
}
std::vector<float> GetPpsHistory()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return std::vector<float>(g_ppsHistory.begin(), g_ppsHistory.end());
}

std::tuple<float, float, float, float> GetProtocolCounts()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    float tcp = 0, udp = 0, icmp = 0, other = 0;
    for (auto& pkt : g_packets)
    {
        if (pkt.protocol == "TCP") tcp += 1.0f;
        else if (pkt.protocol == "UDP") udp += 1.0f;
        else if (pkt.protocol == "ICMP") icmp += 1.0f;
        else other += 1.0f;
    }
    return { tcp, udp, icmp, other };
}

// --- Top hosts ---
std::vector<std::pair<std::string, float>> GetTopHosts(size_t maxHosts)
{
    std::lock_guard<std::mutex> lock(g_mutex);

    std::vector<std::pair<std::string, float>> result;
    for (auto& [ip, traffic] : g_hostTraffic) {
        float totalKB = float(traffic.bytesIn + traffic.bytesOut) / 1024.0f;
        result.emplace_back(ip, totalKB);
    }

    std::sort(result.begin(), result.end(),
        [](auto& a, auto& b) { return a.second > b.second; });

    if (result.size() > maxHosts)
        result.resize(maxHosts);

    return result;
}

Metrics GetMetrics()
{
    Metrics m{};
    auto [bpsVal, ppsVal] = GetBandwidthAndPps();
    m.totalPackets = g_totalPackets.load();
    m.totalBytes = g_totalBytes.load();
    m.bps = bpsVal;
    m.pps = ppsVal;

    // Optional: store last latency/jitter somewhere if you have those; else zero
    m.lastLatency = 0.0;
    m.jitter = 0.0;

    return m;
}