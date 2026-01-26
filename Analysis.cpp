#include "Analysis.h"
#include "AppBandwidth.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mutex>
#include <deque>
#include <algorithm>
#include <chrono>
#include <numeric>
#include <iphlpapi.h>
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "iphlpapi.lib")

/* ---------------- TO DO ----------------
Implement better jitter + latency calculation
Implement full IPv6 support
Add filtering options
Find better way to get app bandwidth
Implement hex view or more detailed view for packets
Optimize packet and flow storage
Implement better flow timeout and cleanup
*/

struct AdapterInfo {
    std::string FriendlyName;
    std::string Description;
    std::string MacAddress;
    uint64_t LinkSpeed;
	ULONG IfIndex;
};

static std::mutex g_mutex;
static std::deque<std::string> g_debugLog;
static constexpr size_t MAX_DEBUG_LINES = 200;

// ---------------- Packet storage ----------------
static std::deque<Packet> g_packets;
constexpr size_t MAX_PACKETS = 50000;

// ---------------- Metrics ----------------
static Metrics g_metrics;
static std::deque<float> g_bpsHistory(300, 0.0f);
static std::deque<float> g_upBpsHistory(300, 0.0f);
static std::deque<float> g_downBpsHistory(300, 0.0f);
static std::deque<float> g_ppsHistory(300, 0.0f);
static std::deque<float> g_latencyHistory(300, 0.0f);
static std::deque<float> g_jitterHistory(300, 0.0f);
static std::deque<Protocols> g_protocolHistory(300, Protocols{0,0,0,0});
static double lastLatency = 0;
static uint64_t lastNicIn = 0;
static uint64_t lastNicOut = 0;
Protocols g_currentProtocolBytes;


static std::unordered_map<size_t, Flow> g_flows;

std::optional<AdapterInfo> g_physicalAdapter;
ULONG g_activeIfIndex = 0;
std::optional<GUID> g_activeAdapterGuid;


static void DebugLog(const std::string& s)
{
    g_debugLog.push_back(s);
    if (g_debugLog.size() > MAX_DEBUG_LINES)
        g_debugLog.pop_front();
}

std::string WideStringToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();

    // Get the size needed for the UTF-8 string
    int size_needed = WideCharToMultiByte(
        CP_UTF8,            // convert to UTF-8
        0,                  // no special flags
        wstr.c_str(),       // input wide string
        (int)wstr.length(), // length of input
        nullptr, 0,         // no output buffer yet
        nullptr, nullptr
    );

    std::string result(size_needed, 0);

    // Perform the actual conversion
    WideCharToMultiByte(
        CP_UTF8,
        0,
        wstr.c_str(),
        (int)wstr.length(),
        &result[0],
        size_needed,
        nullptr, nullptr
    );

    return result;
}

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty())
        return {};

    int size = MultiByteToWideChar(
        CP_UTF8,
        0,
        s.c_str(),
        (int)s.size(),
        nullptr,
        0
    );

    std::wstring result(size, 0);
    MultiByteToWideChar(
        CP_UTF8,
        0,
        s.c_str(),
        (int)s.size(),
        &result[0],
        size
    );

    return result;
}

std::vector<AdapterInfo> GetAdapters()
{
    std::vector<AdapterInfo> adapters;
    g_physicalAdapter.reset(); // important

    ULONG outBufLen = 0;
    DWORD dwRetVal = GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, nullptr, &outBufLen);
    if (dwRetVal != ERROR_BUFFER_OVERFLOW)
        return adapters;

    std::vector<BYTE> buffer(outBufLen);
    auto* pAddresses =
        reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

    dwRetVal = GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, pAddresses, &outBufLen);
    if (dwRetVal != NO_ERROR)
        return adapters;

    for (auto* pCurr = pAddresses; pCurr; pCurr = pCurr->Next)
    {
        AdapterInfo adapter{};

        adapter.FriendlyName = WideStringToUtf8(pCurr->FriendlyName);
        adapter.Description = WideStringToUtf8(pCurr->Description);
        adapter.IfIndex = pCurr->IfIndex;

        if (pCurr->TransmitLinkSpeed > 0 &&
            pCurr->TransmitLinkSpeed != UINT64_MAX)
        {
            adapter.LinkSpeed = pCurr->TransmitLinkSpeed;
        }

        char macAddr[18] = {};
        for (ULONG i = 0; i < pCurr->PhysicalAddressLength; ++i)
        {
            sprintf_s(macAddr + i * 3, sizeof(macAddr) - i * 3,
                (i + 1 == pCurr->PhysicalAddressLength) ? "%02X" : "%02X-",
                pCurr->PhysicalAddress[i]);
        }
        adapter.MacAddress = macAddr;

        if (g_activeAdapterGuid)
        {
            GUID winGuid{};
            if (ConvertInterfaceLuidToGuid(&pCurr->Luid, &winGuid) == NO_ERROR)
            {
                if (IsEqualGUID(winGuid, *g_activeAdapterGuid))
                {
                    g_physicalAdapter = adapter;
                }
            }
        }
        /*char dbg[256];
        snprintf(dbg, sizeof(dbg),
            "[ADAPTER] IfIndex=%lu Name=%s LinkSpeed=%llu\n",
            pCurr->IfIndex,
            adapter.FriendlyName.c_str(),
            (unsigned long long)pCurr->TransmitLinkSpeed);
        DebugLog(dbg);
        DebugLog("[PCAP] Active IfIndex=" + std::to_string(g_activeIfIndex));
        */
        adapters.push_back(std::move(adapter));

    }

    return adapters;
}


bool ExtractGuidFromNpcapName(const std::string& name, GUID& guid) {
    size_t start = name.find('{');
    size_t end = name.find('}');
    if (start == std::string::npos || end == std::string::npos)
        return false;

    std::wstring wguid = Utf8ToWide(name.substr(start, end - start + 1));
    return CLSIDFromString(wguid.c_str(), &guid) == S_OK;
}

bool ResolveIfIndexFromPcapDevice(const std::string& devName) {
    GUID guid{};
    if (!ExtractGuidFromNpcapName(devName, guid))
        return false;

    NET_LUID luid{};
    if (ConvertInterfaceGuidToLuid(&guid, &luid) != NO_ERROR)
        return false;

    NET_IFINDEX ifIndex{};
    if (ConvertInterfaceLuidToIndex(&luid, &ifIndex) != NO_ERROR)
        return false;

    g_activeIfIndex = ifIndex;
    g_activeAdapterGuid = guid;
    GetAdapters();
    return true;
}

bool GetNicBytes(NET_IFINDEX ifIndex,
    uint64_t& inBytes,
    uint64_t& outBytes)
{
    MIB_IF_ROW2 row{};
    row.InterfaceIndex = ifIndex;

    if (GetIfEntry2(&row) != NO_ERROR)
        return false;

    inBytes = row.InOctets;
    outBytes = row.OutOctets;
    return true;
}

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
    FlowKey key;

    if (pkt.protocol == "TCP" || pkt.protocol == "UDP") {
        if (pkt.srcIP < pkt.dstIP ||
            (pkt.srcIP == pkt.dstIP && pkt.srcPort < pkt.dstPort)) {
            key = { pkt.srcIP, pkt.dstIP, pkt.srcPort, pkt.dstPort, pkt.protocolId };
        }
        else {
            key = { pkt.dstIP, pkt.srcIP, pkt.dstPort, pkt.srcPort, pkt.protocolId };
        }
    }
    else if (pkt.protocol == "ICMP") {
        if (pkt.srcIP < pkt.dstIP) {
            key = { pkt.srcIP, pkt.dstIP, 0, 0, IPPROTO_ICMP };
        }
        else {
            key = { pkt.dstIP, pkt.srcIP, 0, 0, IPPROTO_ICMP };
        }
    }
    else {
        key = { pkt.srcIP, pkt.dstIP, pkt.srcPort, pkt.dstPort, pkt.protocolId };
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
        g_metrics.totalBytesDown += pkt.length;
    }
    else {
        flow.stats.bytesUp += pkt.length;
        flow.stats.packetsUp++;
        g_metrics.totalBytesUp += pkt.length;
    }

    if (pkt.protocol == "TCP") {
        auto& stats = flow.stats;
        double now = Now();

        bool usedTimestamp = false;

		// TCP Timestamp RTT
        if (pkt.tcpTsVal != 0 || pkt.tcpTsEcr != 0) {

            if (pkt.isOutbound && pkt.tcpTsVal != 0) {
                stats.tcpTsSent[pkt.tcpTsVal] = now;
            }

            if (!pkt.isOutbound && pkt.tcpTsEcr != 0) {
                auto it = stats.tcpTsSent.find(pkt.tcpTsEcr);
                if (it != stats.tcpTsSent.end()) {
                    double rttMs = (now - it->second) * 1000.0;
					g_metrics.latency = rttMs;

                    stats.tcpTsSent.erase(it);
                    usedTimestamp = true;
                }
            }
        }

        // SEQ/ACK RTT (fallback only)
        if (!usedTimestamp) {
            if (pkt.isOutbound && pkt.tcpPayloadLen > 0) {
                uint32_t endSeq = pkt.tcpSeq + pkt.tcpPayloadLen;
                stats.tcpOutstanding[endSeq] = { now, endSeq };
            }

            if (!pkt.isOutbound && pkt.tcpAck != 0) {
                auto it = stats.tcpOutstanding.upper_bound(pkt.tcpAck);
                if (it != stats.tcpOutstanding.begin()) {
                    --it;

                    double rttMs = (now - it->second.sendTime) * 1000.0;
                    g_metrics.latency = rttMs;

                    stats.tcpOutstanding.erase(it);
                }
            }
        }

        if (pkt.isOutbound && pkt.tcpPayloadLen > 0) {

            if (!stats.seqUpInitialized) {
                stats.nextSeqUp = pkt.tcpSeq + pkt.tcpPayloadLen;
                stats.seqUpInitialized = true;
            }
            else if (pkt.tcpSeq == stats.nextSeqUp) {
                stats.nextSeqUp += pkt.tcpPayloadLen;
            }
        }
        if (!pkt.isOutbound && pkt.tcpPayloadLen > 0) {

            if (!stats.seqDownInitialized) {
                stats.nextSeqDown = pkt.tcpSeq + pkt.tcpPayloadLen;
                stats.seqDownInitialized = true;
            }
            else if (pkt.tcpSeq == stats.nextSeqDown) {
                stats.nextSeqDown += pkt.tcpPayloadLen;
            }
        }
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
                if (flow.stats.latencyHistory.size() >= 2) {
                    double lastLatency = flow.stats.latencyHistory[flow.stats.latencyHistory.size() - 2];
                    double jitter = std::abs(rttMs - lastLatency);
                    flow.stats.jitterHistory.push_back(jitter);

                    if (flow.stats.jitterHistory.size() > flow.stats.maxHistory)
                        flow.stats.jitterHistory.erase(flow.stats.jitterHistory.begin());
                }
                if (flow.stats.latencyHistory.size() > flow.stats.maxHistory)
                    flow.stats.latencyHistory.erase(flow.stats.latencyHistory.begin());
                flow.stats.icmpRequests.erase(it);
                flow.stats.echoReplies++;
            }
        }

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
    Protocols protocolBytes;

    static uint64_t lastBytes = 0;
    static uint64_t lastPackets = 0;
    static uint64_t lastUp = 0;
    static uint64_t lastDown = 0;

    uint64_t bytes = g_metrics.totalBytes;
    uint64_t packets = g_metrics.totalPackets;
    uint64_t up = g_metrics.totalBytesUp;
    uint64_t down = g_metrics.totalBytesDown;

    double bps = (bytes - lastBytes) / dt;
    double pps = (packets - lastPackets) / dt;
    double upBps = (up - lastUp) / dt;
    double downBps = (down - lastDown) / dt;
    float latencyMs = g_metrics.latency;
    float jitterMs = g_metrics.jitter;
    if (!std::isfinite(latencyMs))
        latencyMs = NAN;
    if (!std::isfinite(jitterMs))
        jitterMs = NAN;

    lastBytes = bytes;
    lastPackets = packets;
    lastUp = up;
    lastDown = down;
    double delta = std::abs(latencyMs - lastLatency);
    jitterMs = 0.9 * jitterMs + 0.1 * delta;
	lastLatency = latencyMs;

	protocolBytes.tcpBytes = g_currentProtocolBytes.tcpBytes / 1024;
	protocolBytes.udpBytes = g_currentProtocolBytes.udpBytes / 1024;
	protocolBytes.icmpBytes = g_currentProtocolBytes.icmpBytes / 1024;
	protocolBytes.otherBytes = g_currentProtocolBytes.otherBytes / 1024;

    double protoSum = protocolBytes.tcpBytes + protocolBytes.udpBytes + protocolBytes.icmpBytes + protocolBytes.otherBytes;

    if (g_bpsHistory.size() >= 300) g_bpsHistory.pop_front();
    if (g_ppsHistory.size() >= 300) g_ppsHistory.pop_front();
    if (g_upBpsHistory.size() >= 300) g_upBpsHistory.pop_front();
    if (g_downBpsHistory.size() >= 300) g_downBpsHistory.pop_front();
    if (g_latencyHistory.size() >= 50) g_latencyHistory.pop_front();
    if (g_jitterHistory.size() >= 50) g_jitterHistory.pop_front();
	if (g_protocolHistory.size() >= 300) g_protocolHistory.pop_front();

    g_bpsHistory.push_back((float)bps);
    g_ppsHistory.push_back((float)pps);
    g_upBpsHistory.push_back((float)upBps);
    g_downBpsHistory.push_back((float)downBps);
    g_latencyHistory.push_back((float)latencyMs);
    g_jitterHistory.push_back((float)jitterMs);
	g_protocolHistory.push_back(protocolBytes);

    g_metrics.timeElapsed += dt;
    g_metrics.bps = bps;
    g_metrics.pps = pps;
	g_metrics.latency = latencyMs;
    g_metrics.jitter = jitterMs;
    g_metrics.packetLoss = ComputePacketLoss();
	g_currentProtocolBytes = { 0,0,0,0 };

    uint64_t nicIn = 0, nicOut = 0;
    bool nicOk = GetNicBytes(g_activeIfIndex, nicIn, nicOut);

    double nicBps = 0.0;
    if (nicOk && lastNicIn != 0) {
        uint64_t nicDelta = (nicIn + nicOut) - (lastNicIn + lastNicOut);
        nicBps = nicDelta / dt;
    }

    lastNicIn = nicIn;
    lastNicOut = nicOut;
    g_metrics.nicBps = nicBps;
    double visibility = 0.0;
    if (nicBps > 0.0) {
        visibility = bps / nicBps;
    }
    g_metrics.captureVisibility = visibility;
    g_metrics.linkSpeedBps =
        (g_physicalAdapter && g_physicalAdapter->LinkSpeed > 0)
        ? (double)g_physicalAdapter->LinkSpeed
        : 0.0;

    static uint64_t lastTotalBytes = 0;
    uint64_t totalBytes = g_metrics.totalBytes;
    uint64_t bytesDelta = totalBytes - lastTotalBytes;
    lastTotalBytes = totalBytes;

    double bbps = bytesDelta / dt;
    double mbps = bbps * 8.0 / 1e6;
    double bpsObserved = bytesDelta / dt;
    double mbpsObserved = (bytesDelta * 8.0) / (dt * 1e6);
    double mbpsLink = 0.0;
    if (g_physicalAdapter && g_physicalAdapter->LinkSpeed > 0) {
        mbpsLink = g_physicalAdapter->LinkSpeed / 1e6;
    }

    std::string linkSpeedStr = "unknown";
    if (g_physicalAdapter && g_physicalAdapter->LinkSpeed > 0) {
        linkSpeedStr = std::to_string(g_physicalAdapter->LinkSpeed / 1e6) + " Mbps";
    }

    UpdateAppBandwidth(dt);
    /*
    char buf[256];
    snprintf(buf, sizeof(buf),
        "[LAT] push %.2f ms (size=%zu)",
        latencyMs,
        g_latencyHistory.size()
    );
    DebugLog(buf);

    snprintf(buf, sizeof(buf),
        "Protocols %.2f MB/s  Observed %.2f MB/s\n",
            protoSum,
            g_metrics.bps / 1024
    );
    DebugLog(buf);
    */
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
    if (g_latencyHistory.empty())
        return 0.0;

    size_t count = 0;
    double sum = 0.0;

    for (float v : g_latencyHistory) {
        if (std::isfinite(v)) {
            sum += v;
            count++;
        }
    }
    return count ? (sum / count) : 0.0;
}

double ComputeAverageJitter() {
    if (g_jitterHistory.empty())
        return 0.0;

    size_t count = 0;
    double sum = 0.0;

    for (float v : g_jitterHistory) {
        if (std::isfinite(v)) {
            sum += v;
            count++;
        }
    }
    return count ? (sum / count) : 0.0;
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
    std::lock_guard<std::mutex> lock(g_mutex);
    return { g_latencyHistory.begin(), g_latencyHistory.end() };
}

std::vector<float> GetJitterHistory()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return { g_jitterHistory.begin(), g_jitterHistory.end() };
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

std::vector<float> GetUpBpsHistory()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return { g_upBpsHistory.begin(), g_upBpsHistory.end() };
}

std::vector<float> GetDownBpsHistory()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return { g_downBpsHistory.begin(), g_downBpsHistory.end() };
}


std::vector<Protocols> GetProtocolBandwidthHistory()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return { g_protocolHistory.begin(), g_protocolHistory.end() };
}

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

std::vector<std::string> GetDebugLog()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return { g_debugLog.begin(), g_debugLog.end() };
}