#include "Gui.h"
#include "Capture.h"
#include "Analysis.h"
#include "imgui.h"
#include <vector>
#include <cmath>
#include <algorithm>

// For pie chart
#ifndef PI_F
#define PI_F 3.14159265358979323846f
#endif

static int selectedDevice = -1;
static char filterIP[64] = "";
static int filterPort = 0;
static char filterProto[8] = "";
static int selectedPacket = -1;

// ---------------- Pie drawing ----------------
static void DrawPie(ImDrawList* dl, const ImVec2& center, float radius, float a0, float a1, ImU32 color, int num_segments = 64)
{
    std::vector<ImVec2> pts;
    pts.reserve(num_segments + 2);
    pts.push_back(center);
    int segs = std::max(6, num_segments);
    for (int i = 0; i <= segs; ++i) {
        float t = (float)i / (float)segs;
        float a = a0 + (a1 - a0) * t;
        pts.push_back(ImVec2(center.x + std::cos(a) * radius, center.y + std::sin(a) * radius));
    }
    dl->AddConvexPolyFilled(pts.data(), (int)pts.size(), color);
}

// ---------------- Render GUI ----------------
void RenderGui(float dt)
{
    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(io.DisplaySize);
    ImGui::Begin("Dashboard", nullptr,
        ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoCollapse);

    // --- Top Controls ---
    auto devices = GetAvailableDevices();
    if (ImGui::BeginCombo("Interface", selectedDevice >= 0 ? devices[selectedDevice].description.c_str() : "Select...")) {
        for (int i = 0; i < (int)devices.size(); ++i) {
            bool sel = (selectedDevice == i);
            if (ImGui::Selectable(devices[i].description.c_str(), sel)) selectedDevice = i;
            if (sel) ImGui::SetItemDefaultFocus();
        }
        ImGui::EndCombo();
    }

    if (!IsCapturing()) {
        ImGui::SameLine();
        if (selectedDevice >= 0 && ImGui::Button("Start Capture")) {
            StartCapture(selectedDevice, "");
        }
    }
    else {
        ImGui::SameLine();
        if (ImGui::Button("Stop Capture")) {
            StopCapture();
        }
    }

    ImGui::SameLine();
    if (ImGui::Button("Save PCAP")) {
        SavePcap("capture.pcap");
    }

    ImGui::Separator();

    static double metricAccumulator = 0.0;
    metricAccumulator += dt;

    // Update metrics every 200 ms
    if (metricAccumulator >= 0.2)
    {
        UpdateMetrics(metricAccumulator);
        metricAccumulator = 0.0;
    }

    // --- Metrics ---
    auto metrics = GetMetrics();
    ImGui::Text("Packets: %llu", metrics.totalPackets);
    ImGui::Text("Bytes: %llu", metrics.totalBytes);
    ImGui::Text("Bandwidth: %.2f KB/s", metrics.bps / 1024.0);
    ImGui::Text("PPS: %.2f", metrics.pps);
    ImGui::Text("Last Latency: %.3f ms", metrics.lastLatency);
    ImGui::Text("Jitter: %.3f ms", metrics.jitter);

    ImGui::Separator();

    // --- Filters ---
    ImGui::InputText("Filter IP", filterIP, sizeof(filterIP));
    ImGui::InputInt("Filter Port", &filterPort);
    ImGui::InputText("Filter Proto", filterProto, sizeof(filterProto));

    ImGui::Separator();

    // --- Layout ---
    ImGui::Columns(2, nullptr, true);
    float colWidth = ImGui::GetColumnWidth();
    float colHeight = ImGui::GetContentRegionAvail().y;

    // --- Left: Graphs + Pie Chart ---
    auto bpsHistory = GetBpsHistory();
    auto ppsHistory = GetPpsHistory();

    ImGui::Text("Bandwidth");
    ImGui::PlotLines("##Bandwidth", bpsHistory.data(), (int)bpsHistory.size(), 0, nullptr, 0.0f, FLT_MAX, ImVec2(0, colHeight / 4.0f));
    ImGui::Text("PPS");
    ImGui::PlotLines("##PPS", ppsHistory.data(), (int)ppsHistory.size(), 0, nullptr, 0.0f, FLT_MAX, ImVec2(0, colHeight / 4.0f));

    // Protocol Pie Chart
    float tcp, udp, icmp, other;
    std::tie(tcp, udp, icmp, other) = GetProtocolCounts();
    float total = tcp + udp + icmp + other;
    ImGui::Separator();
    ImGui::Text("Protocol Distribution");
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 pieCenter = ImGui::GetCursorScreenPos();
    float pieRadius = std::min(colWidth, colHeight / 4.0f) * 0.25f + 50.0f;
    ImGui::Dummy(ImVec2(0.0f, pieRadius * 2.0f + 10.0f));

    float a = -PI_F * 0.5f;
    if (total > 0.0f) {
        auto drawSlice = [&](float count, ImU32 col) {
            if (count <= 0.0f) return;
            float ang = (count / total) * (2.0f * PI_F);
            DrawPie(dl, ImVec2(pieCenter.x + pieRadius, pieCenter.y + pieRadius), pieRadius, a, a + ang, col, 64);
            a += ang;
            };
        drawSlice(tcp, IM_COL32(51, 204, 51, 255));
        drawSlice(udp, IM_COL32(51, 102, 230, 255));
        drawSlice(icmp, IM_COL32(255, 153, 51, 255));
        drawSlice(other, IM_COL32(204, 204, 204, 255));
    }

    ImGui::SameLine();
    ImGui::BeginGroup();
    ImGui::Text("TCP: %.0f", tcp);
    ImGui::Text("UDP: %.0f", udp);
    ImGui::Text("ICMP: %.0f", icmp);
    ImGui::Text("Other: %.0f", other);
    ImGui::EndGroup();
    ImGui::Separator();
    ImGui::Text("Top Talkers (Hosts)");

    auto topHosts = GetTopHosts(5);

    // Normalize bars
    float maxKB = 1.0f;
    for (const auto& h : topHosts)
        maxKB = std::max(maxKB, h.second);

    for (const auto& [ip, kb] : topHosts)
    {
        float frac = kb / maxKB;

        ImGui::ProgressBar(
            frac,
            ImVec2(-1.0f, 0.0f),
            (ip + "  " + std::to_string((int)kb) + " KB").c_str()
        );
    }

    ImGui::NextColumn();

    // --- Right: Packet List (Last 30) ---
    auto packets = GetRecentPackets(30);
    ImGui::Text("Packet List (Last 30)");
    float childHeight = colHeight / 1.8f;
    ImGui::BeginChild("PacketListChild", ImVec2(0, childHeight), true, ImGuiWindowFlags_HorizontalScrollbar);

    for (int i = 0; i < packets.size(); ++i) {
        const auto& pkt = packets[i];
        ImGui::PushID(i);
        ImVec4 col = ImVec4(1, 1, 1, 1);
        if (pkt.protocol == "TCP") col = ImVec4(0.4f, 1.0f, 0.4f, 1.0f);
        else if (pkt.protocol == "UDP") col = ImVec4(0.4f, 0.4f, 1.0f, 1.0f);
        else if (pkt.protocol == "ICMP") col = ImVec4(1.0f, 0.6f, 0.4f, 1.0f);

        ImGui::PushStyleColor(ImGuiCol_Text, col);
        std::string label = pkt.srcIP + ":" + std::to_string(pkt.srcPort) + " -> " + pkt.dstIP + ":" + std::to_string(pkt.dstPort) + " " + pkt.protocol;
        ImGui::Selectable(label.c_str(), selectedPacket == i);
        ImGui::PopStyleColor();
        ImGui::PopID();
    }

    ImGui::EndChild();
    ImGui::Columns(1);
    ImGui::End();
}
