#define WIN32_LEAN_AND_MEAN
#include "AppBandwidth.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <psapi.h>

#include <unordered_map>
#include <vector>
#include <string>
#include <algorithm>
#include <mutex>
#include <unordered_set>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")

static std::unordered_map<DWORD, AppDisplay> g_appTotals;
static std::unordered_map<DWORD, std::string> g_pidToName;
static std::mutex g_appMutex;
static constexpr uint64_t MAX_CONN_DELTA = 100ULL * 1024 * 1024;

struct AppCounter {
    uint64_t lastIn = 0;
    uint64_t lastOut = 0;
    double rateMB = 0.0;
};

struct TcpConnKey {
    DWORD pid;
    uint32_t localAddr;
    uint32_t remoteAddr;
    uint16_t localPort;
    uint16_t remotePort;

    bool operator==(const TcpConnKey& o) const {
        return pid == o.pid &&
            localAddr == o.localAddr &&
            remoteAddr == o.remoteAddr &&
            localPort == o.localPort &&
            remotePort == o.remotePort;
    }
};

struct TcpConnHash {
    size_t operator()(const TcpConnKey& k) const {
        size_t h = std::hash<DWORD>()(k.pid);
        h ^= std::hash<uint32_t>()(k.localAddr) << 1;
        h ^= std::hash<uint32_t>()(k.remoteAddr) << 2;
        h ^= std::hash<uint16_t>()(k.localPort) << 3;
        h ^= std::hash<uint16_t>()(k.remotePort) << 4;
        return h;
    }
};

static std::unordered_map<TcpConnKey, uint64_t, TcpConnHash> g_connLastBytes;
static std::unordered_map<DWORD, AppCounter> g_apps;
static std::mutex g_mutex;

static std::string GetProcessName(DWORD pid)
{
    char name[MAX_PATH] = "Unknown";
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
        FALSE, pid);
    if (h) {
        GetModuleBaseNameA(h, nullptr, name, MAX_PATH);
        CloseHandle(h);
    }
    return name;
}

static void EnableTcpEstats(const MIB_TCPROW_OWNER_PID& row)
{
    TCP_ESTATS_DATA_RW_v0 rw{};
    rw.EnableCollection = TRUE;

    SetPerTcpConnectionEStats(
        (PMIB_TCPROW)&row,
        TcpConnectionEstatsData,
        (PUCHAR)&rw,
        0,
        sizeof(rw),
        0
    );
}

static bool ReadTcpBytes(
    const MIB_TCPROW_OWNER_PID& row,
    uint64_t& inBytes,
    uint64_t& outBytes)
{
    TCP_ESTATS_DATA_ROD_v0 rod{};
    ULONG rodSize = sizeof(rod);

    if (GetPerTcpConnectionEStats(
        (PMIB_TCPROW)&row,
        TcpConnectionEstatsData,
        nullptr, 0, 0,
        nullptr, 0, 0,
        (PUCHAR)&rod, 0, rodSize
    ) != NO_ERROR)
        return false;

    inBytes = rod.DataBytesIn;
    outBytes = rod.DataBytesOut;
    return true;
}

void UpdateAppBandwidth(double dtSeconds)
{
    if (dtSeconds <= 0.0)
        return;

    std::lock_guard<std::mutex> lock(g_mutex);

    ULONG size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE,
        AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

    std::vector<uint8_t> buffer(size);
    auto* table = (PMIB_TCPTABLE_OWNER_PID)buffer.data();

    if (GetExtendedTcpTable(table, &size, FALSE,
        AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
        return;

    std::unordered_set<TcpConnKey, TcpConnHash> active;
    std::unordered_map<DWORD, uint64_t> frameBytes;

    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];

        TcpConnKey key{
            row.dwOwningPid,
            ntohl(row.dwLocalAddr),
            ntohl(row.dwRemoteAddr),
            ntohs((uint16_t)row.dwLocalPort),
            ntohs((uint16_t)row.dwRemotePort)
        };

        active.insert(key);

        EnableTcpEstats(row);

        uint64_t in = 0, out = 0;
        if (!ReadTcpBytes(row, in, out))
            continue;

        uint64_t total = in + out;
        uint64_t& last = g_connLastBytes[key];

        if (last == 0) {
            last = total;
            continue;
        }

        if (total >= last) {
            uint64_t delta = total - last;

            if (delta <= MAX_CONN_DELTA) {
                g_appTotals[row.dwOwningPid].totalBytes += delta;
                frameBytes[row.dwOwningPid] += delta;
            }
            else {
                last = total;
                continue;
            }
        }

        last = total;

        if (total >= last) {
            uint64_t delta = total - last;

            g_appTotals[row.dwOwningPid].totalBytes += delta;
            frameBytes[row.dwOwningPid] += delta;
        }

        last = total;
    }

    for (auto it = g_connLastBytes.begin(); it != g_connLastBytes.end(); ) {
        if (!active.contains(it->first))
            it = g_connLastBytes.erase(it);
        else
            ++it;
    }

    for (auto& [pid, bytes] : frameBytes) {
        g_apps[pid].rateMB = (bytes / dtSeconds) / (1024.0 * 1024.0);
    }
}


std::vector<AppDisplay> GetTopApplications(size_t maxApps)
{
    std::lock_guard<std::mutex> lock(g_mutex);

    std::vector<AppDisplay> out;

    for (auto& [pid, totals] : g_appTotals) {
        if (totals.totalBytes == 0)
            continue;

        AppDisplay d{};
        d.name = GetProcessName(pid);
        d.totalBytes = totals.totalBytes;

        auto it = g_apps.find(pid);
        d.rateMB = (it != g_apps.end()) ? it->second.rateMB : 0.0;

        out.push_back(std::move(d));
    }

    std::sort(out.begin(), out.end(),
        [](const AppDisplay& a, const AppDisplay& b) {
            return a.totalBytes > b.totalBytes;
        });

    if (out.size() > maxApps)
        out.resize(maxApps);

    return out;
}
