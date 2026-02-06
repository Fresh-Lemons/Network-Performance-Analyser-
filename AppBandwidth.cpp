// AppBandwidth.cpp
#define WIN32_LEAN_AND_MEAN
#include "AppBandwidth.h"

#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <evntcons.h>
#include <psapi.h>

#include <unordered_map>
#include <vector>
#include <string>
#include <mutex>
#include <thread>
#include <algorithm>
#include <chrono>
#include <deque>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

static std::deque<std::string> g_debugLog;
static constexpr size_t MAX_DEBUG_LINES = 200;
char buf[32];

static void DebugLog(const std::string& s)
{
    g_debugLog.push_back(s);
    if (g_debugLog.size() > MAX_DEBUG_LINES)
        g_debugLog.pop_front();
}

struct AppInternal {
    uint64_t totalBytes = 0;
    uint64_t bytesThisSecond = 0;
    double rateMB = 0.0;
};

static std::unordered_map<DWORD, AppInternal> g_apps;
static std::mutex g_mutex;

static TRACEHANDLE g_sessionHandle = 0;
static TRACEHANDLE g_traceHandle = 0;
static std::thread g_traceThread;
static bool g_running = false;

static const GUID KERNEL_NETWORK_PROVIDER = { 0x7dd42a49, 0x5329, 0x4832, { 0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88 } };
static const GUID SystemTraceControlGuid =
{ 0x9e814aad, 0x3204, 0x11d2,
  { 0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39 } };


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

void WINAPI EventCallback(PEVENT_RECORD record)
{
    DebugLog("Event received");
 
    if (!record)
        return;

    USHORT id = record->EventHeader.EventDescriptor.Id;
    if (id != 10 && id != 11)
        return;

    DWORD pid = record->EventHeader.ProcessId;

    PROPERTY_DATA_DESCRIPTOR desc{};
    desc.PropertyName = (ULONGLONG)L"size";
    desc.ArrayIndex = ULONG_MAX;

    ULONG size = 0;
    ULONG outSize = sizeof(size);

    if (TdhGetProperty(record,
        0,
        nullptr,
        1,
        &desc,
        outSize,
        (PBYTE)&size) != ERROR_SUCCESS)
        return;

    std::lock_guard<std::mutex> lock(g_mutex);

    auto& app = g_apps[pid];
    app.totalBytes += size;
    app.bytesThisSecond += size;
}

static void TraceThread()
{
    ProcessTrace(&g_traceHandle, 1, nullptr, nullptr);
}

bool StartAppBandwidth()
{
    DebugLog("ETW session started");

    if (g_running)
        return false;

    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
    auto* props = (EVENT_TRACE_PROPERTIES*)calloc(1, bufferSize);

    props->Wnode.BufferSize = bufferSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.Guid = SystemTraceControlGuid;
    props->Wnode.ClientContext = 1;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->EnableFlags = EVENT_TRACE_FLAG_NETWORK_TCPIP;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    DebugLog("Here");
    ControlTrace(0, KERNEL_LOGGER_NAME, props, EVENT_TRACE_CONTROL_STOP);

    ULONG status = StartTrace(&g_sessionHandle,
        KERNEL_LOGGER_NAME,
        props);

    if (status != ERROR_SUCCESS)
    {
        DebugLog("Kernel StartTrace failed");
        free(props);
        return false;
    }
    
    EVENT_TRACE_LOGFILE log{};
    log.LoggerName = (LPWSTR)KERNEL_LOGGER_NAME;
    log.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME |
        PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = EventCallback;
    g_traceHandle = OpenTrace(&log);

    g_running = true;
    g_traceThread = std::thread(TraceThread);
    DebugLog("Here2");

    free(props);
    return true;
}

void StopAppBandwidth()
{
    if (!g_running)
        return;

    g_running = false;

    CloseTrace(g_traceHandle);

    ControlTrace(g_sessionHandle,
        L"MyNetSession",
        nullptr,
        EVENT_TRACE_CONTROL_STOP);

    if (g_traceThread.joinable())
        g_traceThread.join();
}

void UpdateAppBandwidth(double dt)
{
    std::lock_guard<std::mutex> lock(g_mutex);

    for (auto& [pid, app] : g_apps) {
        app.rateMB =
            (app.bytesThisSecond / dt) / (1024.0 * 1024.0);

        app.bytesThisSecond = 0;
    }
}

std::vector<AppDisplay> GetTopApplications(size_t maxApps)
{
    std::lock_guard<std::mutex> lock(g_mutex);

    std::vector<AppDisplay> out;

    for (auto& [pid, app] : g_apps) {
        if (app.totalBytes == 0)
            continue;

        AppDisplay d{};
        d.name = GetProcessName(pid);
        d.totalBytes = app.totalBytes;
        d.rateMB = app.rateMB;

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
std::vector<std::string> GetDebugLog1()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return { g_debugLog.begin(), g_debugLog.end() };
}