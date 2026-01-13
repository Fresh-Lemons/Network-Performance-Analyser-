#pragma once

#include <vector>
#include <unordered_map>
#include <string>

std::vector<std::pair<std::string, double>> GetTopApplications(size_t maxApps);
void UpdateAppBandwidth(double dtSeconds);