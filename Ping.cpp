#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WIN32_WINNT 0x0600

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <iphlpapi.h>
#include <Icmpapi.h>

#include <chrono>
#include <cmath>

#include "Ping.h"
#include "Analysis.h"   // for Packet + Now()

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

double Now()
{
    using namespace std::chrono;
    return duration<double>(
        steady_clock::now().time_since_epoch()
    ).count();
}
// ------------------------------------------------------------------
// One-time Winsock init (safe to call multiple times)
// ------------------------------------------------------------------
static void EnsureWinsock()
{
    static bool initialized = false;
    if (!initialized) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
        initialized = true;
    }
}

// ------------------------------------------------------------------

bool Ping::Start(const char* ip, int count)
{
    EnsureWinsock();

    HANDLE icmp = IcmpCreateFile();
    if (icmp == INVALID_HANDLE_VALUE)
        return false;

    IPAddr dst = 0;
    if (InetPtonA(AF_INET, ip, &dst) != 1) {
        IcmpCloseHandle(icmp);
        return false;
    }

    running = true;
    sent = received = 0;
    outstanding.clear();
    rtts.clear();
    jitters.clear();
    lastRtt = -1.0;

    char sendData[32] = "ping";
    char replyBuf[1024];

    for (int i = 0; i < count; ++i) {
        double t0 = Now();

        DWORD res = IcmpSendEcho(
            icmp,
            dst,
            sendData,
            sizeof(sendData),
            nullptr,
            replyBuf,
            sizeof(replyBuf),
            1000
        );

        sent++;

        if (res > 0) {
            auto* reply = (PICMP_ECHO_REPLY)replyBuf;
            double rtt = (double)reply->RoundTripTime;

            rtts.push_back(rtt);
            received++;

            if (lastRtt >= 0.0)
                jitters.push_back(std::abs(rtt - lastRtt));

            lastRtt = rtt;
        }

        Sleep(1000);
    }

    IcmpCloseHandle(icmp);
    running = false;
    return true;
}

// ------------------------------------------------------------------

double Ping::GetAverageLatency() const
{
    if (rtts.empty()) return 0.0;
    double sum = 0.0;
    for (double v : rtts) sum += v;
    return sum / rtts.size();
}

double Ping::GetAverageJitter() const
{
    if (jitters.empty()) return 0.0;
    double sum = 0.0;
    for (double v : jitters) sum += v;
    return sum / jitters.size();
}

double Ping::GetPacketLoss() const
{
    if (sent == 0) return 0.0;
    return 100.0 * (sent - received) / sent;
}