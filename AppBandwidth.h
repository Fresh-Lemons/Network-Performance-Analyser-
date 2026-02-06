#pragma once
#include <vector>
#include <string>

struct AppDisplay {
    std::string name;
    uint64_t totalBytes;
    double rateMB;
};

bool StartAppBandwidth();
void StopAppBandwidth();
void UpdateAppBandwidth(double dtSeconds);
std::vector<AppDisplay> GetTopApplications(size_t maxApps);
std::vector<std::string> GetDebugLog1();