#pragma once
#include <vector>
#include <string>

struct AppDisplay {
    std::string name;
    double totalBytes;
    double rateMB;
};

struct ETWMetrics {
    uint64_t totalBytes = 0;
    uint64_t totalBytesUp = 0;
    uint64_t totalBytesDown = 0;
};

extern ETWMetrics g_etwMetrics;

bool StartAppBandwidth();
void StopAppBandwidth();
void UpdateAppBandwidth(double dtSeconds);
std::vector<AppDisplay> GetTopApplications(size_t maxApps);
std::vector<std::string> GetDebugLog1();
void ResetAppBandwidth();