#pragma once

#include <vector>
#include <unordered_map>
#include <cstdint>

struct Packet; // forward declaration

class Ping {
public:
    bool Start(const char* ip, int count = 4);
    void OnPacket(const Packet& pkt);

    double GetAverageLatency() const;
    double GetAverageJitter() const;
    double GetPacketLoss() const;

    bool IsRunning() const { return running; }

private:
    bool running = false;
    int sent = 0;
    int received = 0;

    std::unordered_map<uint16_t, double> outstanding;
    std::vector<double> rtts;
    std::vector<double> jitters;

    double lastRtt = -1.0;
};
