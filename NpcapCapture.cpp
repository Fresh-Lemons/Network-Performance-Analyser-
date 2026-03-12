#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commdlg.h>
#include "NpcapCapture.h"
#include "Analysis.h"
#include <string>
#include <pcap.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include <cstring>
#include <deque>
#include <chrono>
#include <iomanip>
#include <sstream>

#pragma comment(lib, "Comdlg32.lib")

static std::vector<DeviceInfo> g_devices;
static pcap_t* g_handle = nullptr;
static std::thread g_captureThread;
static std::mutex g_mutex;
static std::atomic<bool> g_running{ false };
static char errbuf[PCAP_ERRBUF_SIZE];
static uint32_t g_localIP = 0;
static std::deque<std::string> g_debugLog;
static constexpr size_t MAX_DEBUG_LINES = 200;

static void DebugLog(const std::string& s)
{
    g_debugLog.push_back(s);
    if (g_debugLog.size() > MAX_DEBUG_LINES)
        g_debugLog.pop_front();
}

std::vector<DeviceInfo> GetAvailableDevices()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_devices.empty()) return g_devices;

    pcap_if_t* alldevs = nullptr;
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
        return {};

    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        g_devices.push_back({ d->name ? d->name : "", d->description ? d->description : d->name ? d->name : "" });
    }
    pcap_freealldevs(alldevs);
    return g_devices;
}

static void PacketHandler(u_char* /*user*/, const struct pcap_pkthdr* header, const u_char* data)
{
    if (!header || !data) return;

    Packet pkt{};
    Protocols& cur = g_currentProtocolBytes;
    pkt.length = header->len;
    pkt.rawData.assign(data, data + header->len);
    const u_char* l3 = data + 14;
    pkt.timestamp = (double)header->ts.tv_sec + (double)header->ts.tv_usec / 1000000.0;

    if (header->caplen < 14 + 20) return;
    uint16_t ethType = (data[12] << 8) | data[13];
    if (ethType == 0x86DD) { // IPv6
        if (header->caplen < 14 + 40)
            return;

        uint8_t nextHeader = l3[6];
        uint16_t payloadLen = ntohs(*(uint16_t*)(l3 + 4));

        if (nextHeader == IPPROTO_TCP && payloadLen >= 20) {
            cur.tcpBytes += payloadLen - 20;
        }
        else if (nextHeader == IPPROTO_UDP && payloadLen >= 8) {
            cur.udpBytes += payloadLen - 8;
        }
        else if (nextHeader == IPPROTO_ICMPV6) {
            cur.icmpBytes += payloadLen;
        }
        else {
            cur.otherBytes += payloadLen;
        }
    }

    const u_char* ip = data + 14;
    uint8_t ihl = (ip[0] & 0x0F) * 4;
    if (ihl < 20) return;

    uint8_t ipProto = ip[9];
    uint32_t srcIP = *(uint32_t*)(ip + 12);
    uint32_t dstIP = *(uint32_t*)(ip + 16);
    pkt.srcIP = std::to_string(srcIP & 0xFF) + "." + std::to_string((srcIP >> 8) & 0xFF) + "." + std::to_string((srcIP >> 16) & 0xFF) + "." + std::to_string((srcIP >> 24) & 0xFF);
    pkt.dstIP = std::to_string(dstIP & 0xFF) + "." + std::to_string((dstIP >> 8) & 0xFF) + "." + std::to_string((dstIP >> 16) & 0xFF) + "." + std::to_string((dstIP >> 24) & 0xFF);

    if (ipProto == 6 && header->caplen >= 14 + ihl + 4) { // TCP
        const u_char* l4 = ip + ihl;
        pkt.srcPort = ntohs(*(uint16_t*)(l4 + 0));
        pkt.dstPort = ntohs(*(uint16_t*)(l4 + 2));
        pkt.tcpSeq = ntohl(*(uint32_t*)(l4 + 4));
        pkt.tcpAck = ntohl(*(uint32_t*)(l4 + 8));
        int32_t dataOffset = (l4[12] >> 4) * 4;
        uint16_t ipTotalLen = ntohs(*(uint16_t*)(ip + 2));
        int32_t payloadLen = (int32_t)ipTotalLen - (int32_t)ihl - (int32_t)dataOffset;
        pkt.tcpPayloadLen = payloadLen;
        cur.tcpBytes += payloadLen;
        pkt.protocol = "TCP";
        pkt.protocolId = IPPROTO_TCP;
        pkt.isOutbound = IsLocalIP(srcIP);

        pkt.tcpTsVal = 0;
        pkt.tcpTsEcr = 0;

        const uint8_t* opt = l4 + 20;
        int optLen = dataOffset - 20;

        while (optLen >= 2) {
            uint8_t kind = opt[0];

            if (kind == 0) break;
            if (kind == 1) {
                opt++;
                optLen--;
                continue;
            }

            uint8_t len = opt[1];
            if (len < 2 || len > optLen) break;

            if (kind == 8 && len == 10) { // Timestamp
                pkt.tcpTsVal = ntohl(*(uint32_t*)(opt + 2));
                pkt.tcpTsEcr = ntohl(*(uint32_t*)(opt + 6));
                break;
            }

            opt += len;
            optLen -= len;
        }
    }
    else if (ipProto == 17 && header->caplen >= 14 + ihl + 4) { // UDP
        const u_char* l4 = ip + ihl;
        pkt.srcPort = ntohs(*(uint16_t*)(l4 + 0));
        pkt.dstPort = ntohs(*(uint16_t*)(l4 + 2));
        uint16_t udpLen = ntohs(*(uint16_t*)(l4 + 4));
        uint16_t payloadLen = udpLen >= 8 ? udpLen - 8 : 0;
        cur.udpBytes += payloadLen;
        pkt.protocol = "UDP";
        pkt.protocolId = IPPROTO_UDP;
        pkt.isOutbound = IsLocalIP(srcIP);
    }
    else if (ipProto == IPPROTO_ICMP && header->caplen >= 14 + ihl + sizeof(IcmpHeader)) {
        pkt.protocol = "ICMP";
        pkt.protocolId = IPPROTO_ICMP;
        uint16_t ipTotalLen = ntohs(*(uint16_t*)(ip + 2));
        uint16_t payloadLen = ipTotalLen - ihl - sizeof(IcmpHeader);
        if (payloadLen > 0)
            cur.icmpBytes += payloadLen;

        const IcmpHeader* icmp = reinterpret_cast<const IcmpHeader*>(ip + ihl);

        pkt.icmpType = icmp->type;
        pkt.icmpId = ntohs(icmp->identifier);
        pkt.icmpSeq = ntohs(icmp->sequence);
        pkt.isOutbound = (pkt.icmpType == 8);
    }

    ProcessPacket(pkt);
}

static bool IsLocalIP(uint32_t ip)
{
    if (g_localIP != 0) {
        return ip == g_localIP;
    }

    uint8_t b1 = ip & 0xFF;
    uint8_t b2 = (ip >> 8) & 0xFF;

    if (b1 == 10) return true;
    if (b1 == 192 && b2 == 168) return true;
    if (b1 == 172 && (b2 >= 16 && b2 <= 31)) return true;

    return false;
}

void InitLocalIP(pcap_if_t* device)
{
    for (pcap_addr_t* addr = device->addresses; addr != NULL; addr = addr->next) {
        if (addr->addr->sa_family == AF_INET) {
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)addr->addr;
            g_localIP = ipv4->sin_addr.s_addr;
            break;
        }
    }
}

static void CaptureLoop()
{
    while (g_running) {
        int ret = pcap_dispatch(g_handle, 0, PacketHandler, nullptr);
        if (ret < 0) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    if (g_handle) {
        pcap_close(g_handle);
        g_handle = nullptr;
    }
}

bool StartCapture(int deviceIndex, const std::string& filter)
{
    std::lock_guard<std::mutex> lock(g_mutex);

    if (g_running)
        return false;

    if (deviceIndex < 0 || deviceIndex >= (int)g_devices.size())
        return false;

    const std::string& devName = g_devices[deviceIndex].name;

    if (!ResolveIfIndexFromPcapDevice(devName))
        return false;

    g_handle = pcap_open_live(devName.c_str(), 65536, 1, 100, errbuf);

    pcap_if_t* alldevs = nullptr;
    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
        for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
            if (devName == d->name) {
                for (pcap_addr_t* a = d->addresses; a != nullptr; a = a->next) {
                    if (a->addr && a->addr->sa_family == AF_INET) {
                        g_localIP = ((struct sockaddr_in*)a->addr)->sin_addr.s_addr;
                        break;
                    }
                }
                break;
            }
        }
        pcap_freealldevs(alldevs);
    }

    if (!g_handle)
        return false;

    if (!filter.empty()) {
        ApplyFilter(filter);
    }

    g_running = true;
    g_captureThread = std::thread(CaptureLoop);

    return true;
}

void StopCapture()
{
    pcap_t* handleToClose = nullptr;

    {
        std::lock_guard<std::mutex> lock(g_mutex);

        if (!g_running)
            return;

        g_running = false;

        if (g_handle) {
            pcap_breakloop(g_handle);
            handleToClose = g_handle;
            g_handle = nullptr;
        }
    }

    if (g_captureThread.joinable())
        g_captureThread.join();

    if (handleToClose)
        pcap_close(handleToClose);
}

bool IsCapturing()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_running;
}

void ApplyFilter(const std::string& filter)
{
    if (!g_handle || filter.empty())
        return;

    bpf_program fp{};
    pcap_compile(g_handle, &fp, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(g_handle, &fp);
    pcap_freecode(&fp);
}

bool SavePcap(const std::string& filename)
{
    std::vector<Packet> packets;

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        packets = GetRecentPackets(500000);
    }

    if (packets.empty())
        return false;

    pcap_t* dead = pcap_open_dead(DLT_EN10MB, 65535);
    if (!dead) return false;

    pcap_dumper_t* dumper = pcap_dump_open(dead, filename.c_str());
    if (!dumper) {
        pcap_close(dead);
        return false;
    }

    for (auto& pkt : packets) {
        struct pcap_pkthdr hdr {};
        hdr.caplen = hdr.len = pkt.length;
        pcap_dump((u_char*)dumper, &hdr, pkt.rawData.data());
    }

    pcap_dump_close(dumper);
    pcap_close(dead);
    return true;
}

std::string GeneratePcapFilename()
{
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);

    std::tm tm{};
    localtime_s(&tm, &time);

    std::ostringstream oss;
    oss << "capture_" << std::put_time(&tm, "%Y%m%d_%H%M%S") << ".pcap";

    return oss.str();
}

std::string ShowSaveFileDialog()
{
    char fileName[MAX_PATH] = "";

    OPENFILENAMEA ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFilter = "PCAP Files (*.pcap)\0*.pcap\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = "pcap";
    ofn.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;

    if (GetSaveFileNameA(&ofn))
    {
        return std::string(fileName);
    }

    return "";
}

std::vector<std::string> GetDebugLog3()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return { g_debugLog.begin(), g_debugLog.end() };
}