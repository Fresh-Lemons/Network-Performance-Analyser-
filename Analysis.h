#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <map>
#include <optional>

// ---------------- Packet ----------------
struct Packet
{
    std::string srcIP;
    std::string dstIP;
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    uint8_t  protocolId = 0;
    std::string protocol;
    uint32_t length = 0;
    bool isOutbound = true;
    std::vector<uint8_t> rawData;
    uint8_t  icmpType = 0;
    uint16_t icmpId = 0;
    uint16_t icmpSeq = 0;
    uint32_t tcpSeq = 0;
    uint32_t tcpAck = 0;
    uint32_t tcpPayloadLen = 0;
    uint32_t tcpTsVal = 0;
    uint32_t tcpTsEcr = 0;
};

#pragma pack(push, 1)

struct EthernetHeader {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
};

struct IPv4Header {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t len;
    uint16_t id;
    uint16_t flags_offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
};

struct IcmpHeader {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence;
};

#pragma pack(pop)

// ---------------- Metrics ----------------
struct Metrics
{
    uint64_t totalPackets = 0;
    uint64_t totalBytes = 0;
    uint64_t totalBytesUp = 0;
	uint64_t totalBytesDown = 0;
    double bps = 0.0;
    double pps = 0.0;
    double totalMB = 0.0;
    double latency = 0.0;
    double jitter = 0.0;
    double packetLoss = 0.0;
    double smoothedLatency = 0.0;
    double nicBps = 0.0;
    double linkSpeedBps = 0.0;
    double captureVisibility = 0.0;
	double timeElapsed = 0.0;
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

    std::vector<double> latencyHistory;     // ms
    std::vector<double> packetLossHistory;  // %
    std::vector<double> jitterHistory;      // ms
    std::vector<double> requestTimes;     
    uint64_t totalRequests = 0;
    uint64_t totalResponses = 0;
    static constexpr size_t maxHistory = 100;

    std::unordered_map<uint16_t, double> icmpRequests;
    uint64_t echoRequests = 0;
    uint64_t echoReplies = 0;

    uint32_t nextSeqUp = 0;
    uint32_t nextSeqDown = 0;
    bool seqUpInitialized = false;
    bool seqDownInitialized = false;

    std::unordered_map<uint32_t, double> tcpTsSent;

    struct TcpOutstanding {
        double sendTime;
        uint32_t endSeq;
    };
    std::map<uint32_t, TcpOutstanding> tcpOutstanding;
};

struct Flow
{
    FlowKey key;
    FlowStats stats;
};

struct Protocols {
    float tcpBytes;
    float udpBytes;
    float icmpBytes;
    float otherBytes;
};

struct AppBandwidth {
    uint64_t bytesSent = 0;
    uint64_t bytesRecv = 0;
};

struct TcpSnapshot {
    uint32_t pid;
    uint32_t localPort;
    uint32_t remotePort;
    uint64_t sent;
    uint64_t recv;
};

// ---------------- Analysis API ----------------
void ProcessPacket(const Packet& pkt);
void UpdateMetrics(double dt);

// GUI queries
Metrics GetMetrics();
std::vector<float> GetBpsHistory();
std::vector<float> GetPpsHistory();
std::vector<Packet> GetRecentPackets(size_t maxCount);
std::vector<float> GetLatencyHistory();
std::vector<float> GetJitterHistory();
std::vector<Protocols> GetProtocolBandwidthHistory();
std::vector<float> GetUpBpsHistory();
std::vector<float> GetDownBpsHistory();
double ComputeAverageJitter();
double ComputeAverageLatency();
double ComputePacketLoss();
bool ResolveIfIndexFromPcapDevice(const std::string& devName);
std::vector<Flow> GetTopFlows(size_t maxFlows);
std::vector<std::pair<std::string, float>> GetTopHosts(size_t maxHosts);
std::vector<std::string> GetDebugLog();
extern Protocols g_currentProtocolBytes;