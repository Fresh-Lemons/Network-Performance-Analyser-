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
        ImGuiWindowFlags_NoCollapse);

    // =====================================================
    // TOP BAR
    // =====================================================
    auto devices = GetAvailableDevices();

    ImGui::PushItemWidth(300);
    if (ImGui::BeginCombo(
        "##iface",
        selectedDevice >= 0 ? devices[selectedDevice].description.c_str() : "Select Interface"))
    {
        for (int i = 0; i < (int)devices.size(); i++) {
            if (ImGui::Selectable(devices[i].description.c_str(), selectedDevice == i))
                selectedDevice = i;
        }
        ImGui::EndCombo();
    }
    ImGui::PopItemWidth();

    ImGui::SameLine();
    if (!IsCapturing()) {
        if (selectedDevice >= 0 && ImGui::Button("Start"))
            StartCapture(selectedDevice, "");
    }
    else {
        if (ImGui::Button("Stop"))
            StopCapture();
    }

    ImGui::SameLine();
    if (ImGui::Button("Save"))
        SavePcap("capture.pcap");

    ImGui::Separator();

    // =====================================================
    // METRICS UPDATE
    // =====================================================
    static double metricAccum = 0.0;
    metricAccum += dt;
    if (metricAccum >= 0.2) {
        UpdateMetrics(metricAccum);
        metricAccum = 0.0;
    }

    Metrics m = GetMetrics();

    // =====================================================
    // SUMMARY CARDS
    // =====================================================
    ImGui::BeginChild("Summary", ImVec2(0, 70), false);
    ImGui::Columns(4, nullptr, false);

    ImGui::Text("Packets\n%llu", m.totalPackets);
    ImGui::NextColumn();
    ImGui::Text("Bandwidth\n%.1f KB/s", m.bps / 1024.0);
    ImGui::NextColumn();
    ImGui::Text("PPS\n%.1f", m.pps);
    ImGui::NextColumn();
    ImGui::Text("Total Data\n%.2f MB", m.totalMB);

    ImGui::Columns(1);
    ImGui::EndChild();

    ImGui::Separator();

    // =====================================================
    // MAIN SPLIT (60 / 40)
    // =====================================================
    float remainingHeight = ImGui::GetContentRegionAvail().y;
    float packetListHeight = remainingHeight * 0.30f;
    float upperHeight = remainingHeight - packetListHeight;

    ImGui::BeginChild("Upper", ImVec2(0, upperHeight), false);
    ImGui::Columns(2, nullptr, true);
    ImGui::SetColumnWidth(0, ImGui::GetWindowWidth() * 0.60f);

    // -----------------------------------------------------
    // LEFT COLUMN (Bandwidth + Protocol)
    // -----------------------------------------------------
    {
        auto bps = GetBpsHistory();

        ImGui::Text("Bandwidth");
        ImGui::PlotLines(
            "##bps",
            bps.data(),
            (int)bps.size(),
            0,
            nullptr,
            0,
            FLT_MAX,
            ImVec2(0, upperHeight * 0.45f));

        ImGui::Separator();

        ImGui::Text("Protocol Bandwidth (placeholder)");
        ImGui::PlotLines(
            "##proto",
            bps.data(),   // reuse for now
            (int)bps.size(),
            0,
            nullptr,
            0,
            FLT_MAX,
            ImVec2(0, upperHeight * 0.35f));
    }

    ImGui::NextColumn();

    // -----------------------------------------------------
    // RIGHT COLUMN (Top Hosts + Flows)
    // -----------------------------------------------------
    {
        ImGui::Text("Top Hosts");
        auto hosts = GetTopHosts(5);

        float maxKB = 1.0f;
        for (auto& h : hosts) maxKB = std::max(maxKB, h.second);

        for (auto& h : hosts) {
            ImGui::ProgressBar(
                h.second / maxKB,
                ImVec2(-1, 0),
                (h.first + "  " + std::to_string((int)h.second) + " KB").c_str());
        }

        ImGui::Separator();

        ImGui::Text("Top Flows");
        ImGui::BeginChild("Flows", ImVec2(0, upperHeight * 0.45f), true);

        auto flows = GetTopFlows(5);
        for (auto& f : flows) {
            ImGui::Text(
                "%s:%d ? %s:%d  (%llu KB)",
                f.key.srcIP.c_str(),
                f.key.srcPort,
                f.key.dstIP.c_str(),
                f.key.dstPort,
                (f.stats.bytesUp + f.stats.bytesDown) / 1024);
        }

        ImGui::EndChild();
    }

    ImGui::Columns(1);
    ImGui::EndChild();

    ImGui::Separator();

    // =====================================================
    // PACKET LIST (FULL WIDTH)
    // =====================================================
    ImGui::Text("Recent Packets");
    ImGui::BeginChild("Packets", ImVec2(0, packetListHeight), true,
        ImGuiWindowFlags_HorizontalScrollbar);

    auto packets = GetRecentPackets(30);
    for (int i = 0; i < (int)packets.size(); i++) {
        const auto& p = packets[i];
        ImGui::PushID(i);

        std::string label =
            p.srcIP + ":" + std::to_string(p.srcPort) +
            " ? " +
            p.dstIP + ":" + std::to_string(p.dstPort) +
            "  " + p.protocol;

        ImGui::Selectable(label.c_str());
        ImGui::PopID();
    }

    ImGui::EndChild();
    ImGui::End();
}
