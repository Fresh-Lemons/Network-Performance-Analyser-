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

static void TraceThread()
{
    ProcessTrace(&g_traceHandle, 1, nullptr, nullptr);
}

void WINAPI EventCallback(PEVENT_RECORD record)
{
    if (!record)
        return;
    
    UCHAR opcode = record->EventHeader.EventDescriptor.Opcode;
    
    if (opcode != 32)
        return;
    
    DWORD pid = record->EventHeader.ProcessId;
    
    if (record->UserDataLength < 36) 
        return;
    
    ULONG* data = (ULONG*)record->UserData;
    ULONG size = data[8];
    
    if (size == 0 || size > 65536)
        return;
    
    std::lock_guard<std::mutex> lock(g_mutex);
    
    auto& app = g_apps[pid];
    app.totalBytes += size;
    app.bytesThisSecond += size;
    
    char buf[128];
    snprintf(buf, sizeof(buf), "PID %u: +%u bytes (total: %llu)", 
        pid, size, app.totalBytes);
    DebugLog(buf);
}

bool StartAppBandwidth()
{
    if (g_running)
        return false;

    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
    auto* props = (EVENT_TRACE_PROPERTIES*)calloc(1, bufferSize);

    props->Wnode.BufferSize = bufferSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->EnableFlags = EVENT_TRACE_FLAG_NETWORK_TCPIP;  
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);


    ControlTrace(0, KERNEL_LOGGER_NAME, props, EVENT_TRACE_CONTROL_STOP);

    ULONG status = StartTrace(&g_sessionHandle, KERNEL_LOGGER_NAME, props);

    if (status != ERROR_SUCCESS) {
        free(props);
        return false;
    }

    EVENT_TRACE_LOGFILE log{};
    log.LoggerName = (LPWSTR)KERNEL_LOGGER_NAME;
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = EventCallback;

    g_traceHandle = OpenTrace(&log);
    if (g_traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        ControlTrace(g_sessionHandle, nullptr, props, EVENT_TRACE_CONTROL_STOP);
        free(props);
        return false;
    }

    g_running = true;
    g_traceThread = std::thread(TraceThread);

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