// app_bandwidth.cpp
#define WIN32_LEAN_AND_MEAN
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

struct AppTraffic {
    uint64_t totalBytes = 0;
    uint64_t lastIn = 0;
    uint64_t lastOut = 0;
};

static std::unordered_map<DWORD, AppTraffic> g_appTotals;
static std::unordered_map<DWORD, std::string> g_pidToName;
static std::mutex g_appMutex;

struct AppCounter {
    uint64_t lastIn = 0;
    uint64_t lastOut = 0;
    double   rateMB = 0.0;
};

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

void UpdateApplicationTraffic()
{
    std::lock_guard<std::mutex> lock(g_appMutex);

    PMIB_TCPTABLE_OWNER_PID table = nullptr;
    ULONG size = 0;

    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET,
        TCP_TABLE_OWNER_PID_ALL, 0);

    table = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (!table) return;

    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET,
        TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
    {
        free(table);
        return;
    }

    for (DWORD i = 0; i < table->dwNumEntries; ++i)
    {
        auto& row = table->table[i];
        DWORD pid = row.dwOwningPid;

        // Enable ESTATS once
        static std::unordered_set<uint64_t> enabled;
        uint64_t key = ((uint64_t)pid << 32) | row.dwLocalPort;
        if (!enabled.count(key)) {
            EnableTcpEstats(row);
            enabled.insert(key);
        }

        uint64_t inBytes = 0, outBytes = 0;
        if (!ReadTcpBytes(row, inBytes, outBytes))
            continue;

        auto& app = g_appTotals[pid];

        uint64_t deltaIn = inBytes - app.lastIn;
        uint64_t deltaOut = outBytes - app.lastOut;

        app.lastIn = inBytes;
        app.lastOut = outBytes;

        app.totalBytes += (deltaIn + deltaOut);

        // Cache process name once
        if (!g_pidToName.count(pid))
            g_pidToName[pid] = GetProcessName(pid);
    }

    free(table);
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
    auto* table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());

    if (GetExtendedTcpTable(table, &size, FALSE,
        AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
        return;

    std::unordered_map<DWORD, uint64_t> curTotals;

    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];

        EnableTcpEstats(row);

        uint64_t in = 0, out = 0;
        if (!ReadTcpBytes(row, in, out))
            continue;

        curTotals[row.dwOwningPid] += in + out;
    }

    for (auto& [pid, total] : curTotals) {
        auto& app = g_apps[pid];
        uint64_t last = app.lastIn + app.lastOut;

        if (last > 0 && total >= last) {
            uint64_t delta = total - last;
            app.rateMB = (delta / dtSeconds) / (1024.0 * 1024.0);
        }

        app.lastIn = total;
        app.lastOut = 0;
    }
}

std::vector<std::pair<std::string, double>>
GetTopApplications(size_t maxApps)
{
    std::lock_guard<std::mutex> lock(g_mutex);

    std::vector<std::pair<std::string, double>> out;

    for (auto& [pid, app] : g_apps) {
        if (app.rateMB > 0.001) {
            out.emplace_back(GetProcessName(pid), app.rateMB);
        }
    }

    std::sort(out.begin(), out.end(),
        [](auto& a, auto& b) { return a.second > b.second; });

    if (out.size() > maxApps)
        out.resize(maxApps);

    return out;
}
