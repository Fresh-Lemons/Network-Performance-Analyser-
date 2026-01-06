#pragma once
#include <vector>
#include <string>

struct DeviceInfo {
    std::string name;
    std::string description;
};

// Enumerate all interfaces
std::vector<DeviceInfo> GetAvailableDevices();

// Start/Stop capture
bool StartCapture(int deviceIndex, const std::string& filter);
bool IsLocalIP(uint32_t ip);
void StopCapture();
bool IsCapturing();
bool SavePcap(const std::string& filename);