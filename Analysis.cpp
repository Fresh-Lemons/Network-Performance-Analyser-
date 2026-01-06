#include "Analysis.h"
#include <mutex>
#include <deque>
#include <algorithm>
#include <chrono>
#include <numeric>

static std::mutex g_mutex;

// ---------------- Packet storage ----------------
static std::deque<Packet> g_packets;
constexpr size_t MAX_PACKETS = 50000;

// ---------------- Metrics ----------------
static Metrics g_metrics;
static std::deque<float> g_bpsHistory(300, 0.0f);
static std::deque<float> g_ppsHistory(300, 0.0f);

// ---------------- Flow storage ----------------
static std::unordered_map<size_t, Flow> g_flows;

// ---------------- Time ----------------
static double Now()
{
    using namespace std::chrono;
    static auto start = high_resolution_clock::now();
    auto now = high_resolution_clock::now();
    return duration<double>(now - start).count();
}

// ---------------- Flow hashing ----------------
static size_t HashFlow(const FlowKey& k)
{
    size_t h = std::hash<std::string>()(k.srcIP);
    h ^= std::hash<std::string>()(k.dstIP) << 1;
    h ^= std::hash<uint16_t>()(k.srcPort) << 2;
    h ^= std::hash<uint16_t>()(k.dstPort) << 3;
    h ^= std::hash<uint8_t>()(k.protocol) << 4;
    return h;
}

// ---------------- Flow update ----------------
static void UpdateFlows(const Packet& pkt)
{
    // In UpdateFlows, at the very top
    FlowKey key;
    if (pkt.protocol == "ICMP") {
        key = {
            pkt.srcIP,
            pkt.dstIP,
            pkt.srcPort, // ICMP identifier
            0,           // ignore sequence
            pkt.protocolId
        };
    }
    else {
        key = {
            pkt.srcIP,
            pkt.dstIP,
            pkt.srcPort,
            pkt.dstPort,
            pkt.protocolId
        };
    }


    size_t h = HashFlow(key);
    auto& flow = g_flows[h];

    double t = Now();

    if (flow.stats.firstSeen == 0.0) {
        flow.key = key;
        flow.stats.firstSeen = t;
    }

    flow.stats.lastSeen = t;

    // bytes/packets counting
    if (!pkt.isOutbound) {
        flow.stats.bytesDown += pkt.length;
        flow.stats.packetsDown++;
    }
    else {
        flow.stats.bytesUp += pkt.length;
        flow.stats.packetsUp++;
    }

    // --- ICMP RTT & packet loss ---
    if (pkt.protocol == "ICMP") {
        if (pkt.icmpType == 8 && pkt.isOutbound) { // Echo Request
            flow.stats.icmpRequests[pkt.icmpSeq] = t;
            flow.stats.echoRequests++;
        }
        else if (pkt.icmpType == 0 && !pkt.isOutbound) { // Echo Reply
            auto it = flow.stats.icmpRequests.find(pkt.icmpSeq);
            if (it != flow.stats.icmpRequests.end()) {
                double rttMs = (t - it->second) * 1000.0;
                flow.stats.latencyHistory.push_back(rttMs);
                flow.stats.icmpRequests.erase(it);
                flow.stats.echoReplies++;
            }
        }

        // optional: update packet loss per flow
        double loss = 0.0;
        if (flow.stats.echoRequests > 0) {
            loss = 100.0 * (flow.stats.echoRequests - flow.stats.echoReplies) / flow.stats.echoRequests;
        }
        if (flow.stats.packetLossHistory.size() >= 100)
            flow.stats.packetLossHistory.erase(flow.stats.packetLossHistory.begin());
        flow.stats.packetLossHistory.push_back(loss);
    }
}



// ---------------- Packet processing ----------------
void ProcessPacket(const Packet& pkt)
{
    std::lock_guard<std::mutex> lock(g_mutex);

    g_packets.push_back(pkt);
    if (g_packets.size() > MAX_PACKETS)
        g_packets.pop_front();

    g_metrics.totalPackets++;
    g_metrics.totalBytes += pkt.length;
    g_metrics.totalMB = g_metrics.totalBytes / (1024.0 * 1024.0);

    UpdateFlows(pkt);
}

// ---------------- Metrics update ----------------
void UpdateMetrics(double dt)
{
    std::lock_guard<std::mutex> lock(g_mutex);

    static uint64_t lastBytes = 0;
    static uint64_t lastPackets = 0;

    uint64_t bytes = g_metrics.totalBytes;
    uint64_t packets = g_metrics.totalPackets;

    double bps = (bytes - lastBytes) / dt;
    double pps = (packets - lastPackets) / dt;

    lastBytes = bytes;
    lastPackets = packets;

    if (g_bpsHistory.size() >= 300) g_bpsHistory.pop_front();
    if (g_ppsHistory.size() >= 300) g_ppsHistory.pop_front();

    g_bpsHistory.push_back((float)bps);
    g_ppsHistory.push_back((float)pps);

    g_metrics.bps = bps;
    g_metrics.pps = pps;

    g_metrics.lastLatency = ComputeAverageLatency();
    g_metrics.jitter = ComputeJitter();
    g_metrics.packetLoss = ComputePacketLoss();
}

// ---------------- GUI getters ----------------
Metrics GetMetrics()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_metrics;
}

std::vector<float> GetBpsHistory()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return { g_bpsHistory.begin(), g_bpsHistory.end() };
}

std::vector<float> GetPpsHistory()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return { g_ppsHistory.begin(), g_ppsHistory.end() };
}

std::vector<Packet> GetRecentPackets(size_t maxCount)
{
    std::lock_guard<std::mutex> lock(g_mutex);

    std::vector<Packet> out;
    if (g_packets.size() > maxCount)
        out.assign(g_packets.end() - maxCount, g_packets.end());
    else
        out.assign(g_packets.begin(), g_packets.end());

    return out;
}
double ComputeAverageLatency() {
    double sum = 0.0;
    size_t count = 0;
    for (auto& [_, f] : g_flows) {
        for (double l : f.stats.latencyHistory) {
            sum += l;
            count++;
        }
    }
    return count ? (sum / count) : 0.0;
}

double ComputeJitter() {
    double sum = 0.0, sumSq = 0.0;
    size_t count = 0;
    for (auto& [_, f] : g_flows) {
        for (double l : f.stats.latencyHistory) {
            sum += l;
            sumSq += l * l;
            count++;
        }
    }
    if (count < 2) return 0.0;
    double mean = sum / count;
    double variance = (sumSq / count) - (mean * mean);
    return std::sqrt(std::max(0.0, variance));
}

double ComputePacketLoss() {
    uint64_t sent = 0, recv = 0;
    for (auto& [_, f] : g_flows) {
        sent += f.stats.echoRequests;
        recv += f.stats.echoReplies;
    }
    if (sent == 0) return 0.0;
    return 100.0 * (double)(sent - recv) / sent;
}


std::vector<float> GetLatencyHistory()
{
    std::vector<float> history;
    for (auto& [h, flow] : g_flows) {
        for (double val : flow.stats.latencyHistory)
            history.push_back(static_cast<float>(val));
    }
    return history;
}

std::vector<float> GetPacketLossHistory()
{
    std::vector<float> history;
    for (auto& [h, flow] : g_flows) {
        for (double val : flow.stats.packetLossHistory)
            history.push_back(static_cast<float>(val));
    }
    return history;
}


std::vector<float> GetProtocolBandwidthHistory()
{
    static std::vector<float> dummy(300, 0.0f);
    return dummy;
}

// ---------------- Flow queries ----------------
std::vector<Flow> GetTopFlows(size_t maxFlows)
{
    std::lock_guard<std::mutex> lock(g_mutex);

    std::vector<Flow> out;
    for (auto& kv : g_flows)
        out.push_back(kv.second);

    std::sort(out.begin(), out.end(),
        [](const Flow& a, const Flow& b) {
            uint64_t ta = a.stats.bytesUp + a.stats.bytesDown;
            uint64_t tb = b.stats.bytesUp + b.stats.bytesDown;
            return ta > tb;
        });

    if (out.size() > maxFlows)
        out.resize(maxFlows);

    return out;
}

std::vector<std::pair<std::string, float>> GetTopHosts(size_t maxHosts)
{
    std::lock_guard<std::mutex> lock(g_mutex);

    std::unordered_map<std::string, uint64_t> totals;

    for (auto& kv : g_flows) {
        const Flow& f = kv.second;
        totals[f.key.srcIP] += f.stats.bytesUp;
        totals[f.key.dstIP] += f.stats.bytesDown;
    }

    std::vector<std::pair<std::string, float>> out;
    for (auto& kv : totals)
        out.emplace_back(kv.first, kv.second / 1024.0f);

    std::sort(out.begin(), out.end(),
        [](auto& a, auto& b) { return a.second > b.second; });

    if (out.size() > maxHosts)
        out.resize(maxHosts);

    return out;
}