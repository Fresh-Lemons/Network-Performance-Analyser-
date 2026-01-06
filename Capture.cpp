#include "Capture.h"
#include "Analysis.h"
#include <pcap.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include <cstring>

static std::vector<DeviceInfo> g_devices;
static pcap_t* g_handle = nullptr;
static std::thread g_captureThread;
static std::mutex g_mutex;
static std::atomic<bool> g_running{ false };
static char errbuf[PCAP_ERRBUF_SIZE];

// ---------------- Device Enumeration ----------------
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

// ---------------- Packet Handler ----------------
static void PacketHandler(u_char* /*user*/, const struct pcap_pkthdr* header, const u_char* data)
{
    if (!header || !data) return;

    Packet pkt{};
    pkt.length = header->len;
    pkt.rawData.assign(data, data + header->len);

    // minimal parsing (Ethernet + IPv4 + TCP/UDP)
    if (header->caplen < 14 + 20) return;
    uint16_t ethType = (data[12] << 8) | data[13];
    if (ethType != 0x0800) return; // IPv4 only

    const u_char* ip = data + 14;
    uint8_t ihl = (ip[0] & 0x0F) * 4;
    if (ihl < 20) return;

    uint8_t ipProto = ip[9];
    uint32_t srcIP = *(uint32_t*)(ip + 12);
    uint32_t dstIP = *(uint32_t*)(ip + 16);
    pkt.srcIP = std::to_string(srcIP & 0xFF) + "." + std::to_string((srcIP >> 8) & 0xFF) +
        "." + std::to_string((srcIP >> 16) & 0xFF) + "." + std::to_string((srcIP >> 24) & 0xFF);
    pkt.dstIP = std::to_string(dstIP & 0xFF) + "." + std::to_string((dstIP >> 8) & 0xFF) +
        "." + std::to_string((dstIP >> 16) & 0xFF) + "." + std::to_string((dstIP >> 24) & 0xFF);

    pkt.srcPort = 0;
    pkt.dstPort = 0;
    pkt.protocol = "OTHER";

    if (ipProto == 6 && header->caplen >= 14 + ihl + 4) { // TCP
        const u_char* l4 = ip + ihl;
        pkt.srcPort = ntohs(*(uint16_t*)(l4 + 0));
        pkt.dstPort = ntohs(*(uint16_t*)(l4 + 2));
        pkt.protocol = "TCP";
    }
    else if (ipProto == 17 && header->caplen >= 14 + ihl + 4) { // UDP
        const u_char* l4 = ip + ihl;
        pkt.srcPort = ntohs(*(uint16_t*)(l4 + 0));
        pkt.dstPort = ntohs(*(uint16_t*)(l4 + 2));
        pkt.protocol = "UDP";
    }
    else if (ipProto == IPPROTO_ICMP && header->caplen >= 14 + ihl + sizeof(IcmpHeader)) {
        pkt.protocol = "ICMP";
        pkt.protocolId = IPPROTO_ICMP;

        const IcmpHeader* icmp =
            reinterpret_cast<const IcmpHeader*>(ip + ihl);

        pkt.icmpType = icmp->type;
        pkt.icmpId = ntohs(icmp->identifier);
        pkt.icmpSeq = ntohs(icmp->sequence);
        pkt.isOutbound = (pkt.icmpType == 8);
    }
    if (pkt.protocol == "ICMP") {
        char buf[256];
        sprintf_s(
            buf,
            "ICMP %s type=%d id=%u seq=%u\n",
            pkt.isOutbound ? "OUT" : "IN",
            pkt.icmpType,
            pkt.icmpId,
            pkt.icmpSeq
        );
        OutputDebugStringA(buf);
    }

    // send packet to Analysis
    ProcessPacket(pkt);
}

static bool IsLocalIP(uint32_t ip)
{
    uint8_t b1 = ip & 0xFF;
    uint8_t b2 = (ip >> 8) & 0xFF;

    // RFC1918 private ranges
    if (b1 == 10) return true;
    if (b1 == 192 && b2 == 168) return true;
    if (b1 == 172 && (b2 >= 16 && b2 <= 31)) return true;

    return false;
}

// ---------------- Capture Thread ----------------
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

// ---------------- Start Capture ----------------
bool StartCapture(int deviceIndex, const std::string& filter)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_running || deviceIndex < 0 || deviceIndex >= g_devices.size()) return false;

    g_handle = pcap_open_live(g_devices[deviceIndex].name.c_str(), 65536, 1, 100, errbuf);
    if (!g_handle) return false;

    // BPF filter
    if (!filter.empty()) {
        bpf_program fp;
        if (pcap_compile(g_handle, &fp, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_setfilter(g_handle, &fp);
            pcap_freecode(&fp);
        }
    }

    g_running = true;
    g_captureThread = std::thread(CaptureLoop);
    return true;
}

// ---------------- Stop Capture ----------------
void StopCapture()
{
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_running = false;
    }
    if (g_captureThread.joinable())
        g_captureThread.join();
}

// ---------------- Is Capturing ----------------
bool IsCapturing()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_running;
}

// ---------------- Save PCAP ----------------
bool SavePcap(const std::string& filename)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_handle) return false;

    std::vector<Packet> packets = GetRecentPackets(50000);
    if (packets.empty()) return false;

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