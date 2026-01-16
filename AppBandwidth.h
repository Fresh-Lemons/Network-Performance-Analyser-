#pragma once

#include <vector>
#include <unordered_map>
#include <string>

struct AppDisplay {
    std::string name;
    double rateMB;
    uint64_t totalBytes;
};

std::vector<AppDisplay> GetTopApplications(size_t maxApps);
void UpdateAppBandwidth(double dtSeconds);