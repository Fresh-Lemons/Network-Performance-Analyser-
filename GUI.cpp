#define NOMINMAX
#define IMPLOT_VERSION_MAJOR

#include "Gui.h"
#include "NpcapCapture.h"
#include "Analysis.h"
#include "Ping.h"
#include "AppBandwidth.h"
#include "imgui.h"
#include "implot.h"
#include <vector>
#include <cmath>
#include <algorithm>
#include <deque>
#include <thread>
#include <mutex>

// For pie chart
#ifndef PI_F
#define PI_F 3.14159265358979323846f
#endif

static int selectedDevice = -1;
static char filterIP[64] = "";
static int filterPort = 0;
static char filterProto[8] = "";
static int selectedPacket = -1;

char Buf[32];
static std::mutex g_mutex;
static std::deque<std::string> g_debugLog;
static constexpr size_t MAX_DEBUG_LINES = 200;
bool g_showSaveMessage = false;
std::string g_saveMessage;

static void DebugLog2(const std::string& s)
{
    g_debugLog.push_back(s);
    if (g_debugLog.size() > MAX_DEBUG_LINES)
        g_debugLog.pop_front();
}
std::vector<std::string> GetDebugLog2()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return { g_debugLog.begin(), g_debugLog.end() };
}

static const char* FormatBytes(uint64_t bytes, char* buf, size_t bufSize)
{
    const char* units[] = { "B", "KB", "MB", "GB", "TB" };
    double value = (double)bytes;
    int unit = 0;

    while (value >= 1024 && unit < 4) {
        value /= 1024.0;
        ++unit;
    }

    snprintf(buf, bufSize, "%.2f %s", value, units[unit]);
    return buf;
}

Ping g_ping;

static void CopyAndScale(const std::vector<float>& src, std::vector<float>& dst, float scale)
{
    dst.resize(src.size());
    for (size_t i = 0; i < src.size(); ++i)
        dst[i] = src[i] * scale;
}

void PlotBandwidthStacked(const std::vector<float>& upBps, const std::vector<float>& downBps)
{
    if (upBps.empty() || downBps.empty())
        return;

    static std::vector<float> up;
    static std::vector<float> down;
    static std::vector<float> total;

    CopyAndScale(upBps, up, 1.0f / 1024.0f);
    CopyAndScale(downBps, down, 1.0f / 1024.0f);

    size_t n = std::min(up.size(), down.size());
    total.resize(n);
    float maxKbps = total.empty() ? 0.0f : *std::max_element(total.begin(), total.end());
    for (size_t i = 0; i < n; ++i)
        total[i] = up[i] + down[i];

    bool running = IsCapturing();
    ImPlot::PushStyleVar(ImPlotStyleVar_PlotPadding, ImVec2(0, 0));
    ImPlot::PushStyleVar(ImPlotStyleVar_LabelPadding, ImVec2(0, 0));

    if (ImPlot::BeginPlot("##Bandwidth", ImVec2(-1, ImGui::GetContentRegionAvail().y / 2), ImPlotFlags_NoLegend | ImPlotFlags_NoMenus))
    {
        ImPlot::SetupAxes(nullptr, nullptr, ImPlotAxisFlags_NoDecorations, ImPlotAxisFlags_NoDecorations | ImPlotAxisFlags_AutoFit);

        ImPlot::SetupAxisLimits(ImAxis_X1, 150, (double)n, ImGuiCond_Always);
        ImPlot::SetupAxisLimits(ImAxis_Y1, 0, maxKbps * 1.1f, ImGuiCond_Always);

        ImPlot::PushStyleColor(ImPlotCol_Fill, ImVec4(0.2f, 0.6f, 1.0f, 0.6f));
        ImPlot::PlotShaded("Download", up.data(), (int)n, 0);
        ImPlot::PopStyleColor();

        ImPlot::PushStyleColor(ImPlotCol_Fill, ImVec4(0.3f, 0.9f, 0.4f, 0.6f));
        ImPlot::PlotShaded("Upload", total.data(), (int)n, 0);
        ImPlot::PopStyleColor();

        ImPlotRect limits = ImPlot::GetPlotLimits();
        ImDrawList* draw = ImPlot::GetPlotDrawList();

        ImVec2 tl = ImPlot::PlotToPixels(limits.X.Min, limits.Y.Max);
        ImVec2 tr = ImPlot::PlotToPixels(limits.X.Max, limits.Y.Max);

        draw->AddText(ImVec2(tl.x + 6, tl.y + 6), IM_COL32(200, 200, 200, 255), "Throughput");

        char buf[64];
        snprintf(buf, sizeof(buf), "%.1f Mbs", maxKbps * 1.1 / 1024);

        draw->AddText(ImVec2(tr.x - ImGui::CalcTextSize(buf).x - 6, tl.y + 6), IM_COL32(200, 200, 200, 255), buf);

        ImPlot::PlotText("30", limits.X.Min, limits.Y.Min, ImVec2(10, -8));
        ImPlot::PlotText("0", limits.X.Max, limits  .Y.Min, ImVec2(-10, -8));

        if (ImPlot::IsPlotHovered()) {
            ImPlotPoint mouse = ImPlot::GetPlotMousePos();
            static double cursorX[2];
            static double cursorY[2];

            cursorX[0] = mouse.x;
            cursorX[1] = mouse.x;

            cursorY[0] = 0;
            cursorY[1] = maxKbps;

            ImPlot::PushStyleColor(ImPlotCol_Line, ImVec4(1, 1, 1, 0.25f));
            ImPlot::PlotLine("##cursor", cursorX, cursorY, 2);
            ImPlot::PopStyleColor();
            int idx = (int)std::round(mouse.x);
            if (idx >= 0 && idx < (int)n) {
                ImGui::BeginTooltip();
                ImGui::Text("Download: %.1f KB/s", down[idx]);
                ImGui::Text("Upload:   %.1f KB/s", up[idx]);
                ImGui::Text("Total:    %.1f KB/s", total[idx]);
                ImGui::EndTooltip();
            }
        }
        ImPlot::EndPlot();
        ImPlot::PopStyleVar();
    }
}

void PlotProtocolStacked(const std::vector<Protocols>& hist)
{
    if (hist.empty())
        return;

    static std::vector<float> tcp, udp, dns, icmp, other, total;

    const int n = (int)hist.size();

    tcp.resize(n);
    udp.resize(n);
    dns.resize(n);
    icmp.resize(n);
    other.resize(n);
    total.resize(n);

    float maxRate = 0.0f;

    for (int i = 0; i < n; ++i) {
        tcp[i] = hist[i].tcpBytes;
        udp[i] = tcp[i] + hist[i].udpBytes;
        icmp[i] = udp[i] + hist[i].icmpBytes;
        other[i] = icmp[i] + hist[i].otherBytes;
        total[i] = other[i];

        maxRate = std::max(maxRate, total[i]);
    }

    ImPlot::PushStyleVar(ImPlotStyleVar_PlotPadding, ImVec2(0, 0));
    ImPlot::PushStyleVar(ImPlotStyleVar_LabelPadding, ImVec2(0, 0));

    if (ImPlot::BeginPlot("##ProtocolStacked", ImVec2(-1, ImGui::GetContentRegionAvail().y / 2), ImPlotFlags_NoLegend | ImPlotFlags_NoMenus))
    {
        ImPlot::SetupAxes(nullptr, nullptr, ImPlotAxisFlags_NoDecorations, ImPlotAxisFlags_NoDecorations | ImPlotAxisFlags_AutoFit);

        ImPlot::SetupAxisLimits(ImAxis_X1, n - 150, n, ImGuiCond_Always);
        ImPlot::SetupAxisLimits(ImAxis_Y1, 0, maxRate * 1.1f, ImGuiCond_Always);

        ImPlot::PushStyleColor(ImPlotCol_Fill, ImVec4(0.30f, 0.55f, 0.90f, 0.7f));
        ImPlot::PlotShaded("TCP", tcp.data(), n, 0);
        ImPlot::PopStyleColor();

        ImPlot::PushStyleColor(ImPlotCol_Fill, ImVec4(0.30f, 0.85f, 0.45f, 0.7f));
        ImPlot::PlotShaded("UDP", udp.data(), n, 0);
        ImPlot::PopStyleColor();

        ImPlot::PushStyleColor(ImPlotCol_Fill, ImVec4(0.85f, 0.40f, 0.40f, 0.7f));
        ImPlot::PlotShaded("ICMP", icmp.data(), n, 0);
        ImPlot::PopStyleColor();

        ImPlot::PushStyleColor(ImPlotCol_Fill, ImVec4(0.60f, 0.60f, 0.60f, 0.7f));
        ImPlot::PlotShaded("Other", other.data(), n, 0);
        ImPlot::PopStyleColor();

        ImPlotRect limits = ImPlot::GetPlotLimits();
        ImDrawList* draw = ImPlot::GetPlotDrawList();

        ImVec2 tl = ImPlot::PlotToPixels(limits.X.Min, limits.Y.Max);
        ImVec2 tr = ImPlot::PlotToPixels(limits.X.Max, limits.Y.Max);

        draw->AddText(ImVec2(tl.x + 6, tl.y + 6), IM_COL32(200, 200, 200, 255), "Protocol bandwidth");

        char buf[64];
        snprintf(buf, sizeof(buf), "%.1f KB/s", maxRate);

        draw->AddText(ImVec2(tr.x - ImGui::CalcTextSize(buf).x - 6, tl.y + 6), IM_COL32(200, 200, 200, 255), buf);

        ImPlot::PlotText("30", limits.X.Min, limits.Y.Min, ImVec2(10, -8));
        ImPlot::PlotText("0", limits.X.Max, limits.Y.Min, ImVec2(-10, -8));

        if (ImPlot::IsPlotHovered()) {
            ImPlotPoint mouse = ImPlot::GetPlotMousePos();
            double x[2] = { mouse.x, mouse.x };
            double y[2] = { 0, maxRate };

            ImPlot::PushStyleColor(ImPlotCol_Line, ImVec4(1, 1, 1, 0.25f));
            ImPlot::PlotLine("##cursor", x, y, 2);
            ImPlot::PopStyleColor();

            int idx = (int)std::round(mouse.x);
            if (idx >= 0 && idx < n) {
                ImGui::BeginTooltip();
                ImGui::Text("TCP:   %.1f KB/s", hist[idx].tcpBytes);
                ImGui::Text("UDP:   %.1f KB/s", hist[idx].udpBytes);
                ImGui::Text("ICMP:  %.1f KB/s", hist[idx].icmpBytes);
                ImGui::Text("Other: %.1f KB/s", hist[idx].otherBytes);
                ImGui::EndTooltip();
            }
        }

        ImPlot::EndPlot();
    }

    ImPlot::PopStyleVar(2);
}

void PlotLatency(const std::vector<float>& latencyMs, float graphHeight)
{
    if (latencyMs.empty())
        return;

    const int n = (int)latencyMs.size();
    const int window = 150;
    const int start = n > window ? n - window : 0;
    const int count = n - start;
    static std::vector<float> total;
    float maxLatency = 1.0f;
    for (int i = start; i < n; ++i)
        maxLatency = std::max(maxLatency, latencyMs[i]);

    if (ImPlot::BeginPlot("##Latency (ms)", ImVec2(-1, graphHeight), ImPlotFlags_NoLegend | ImPlotFlags_NoMenus))
    {
        ImPlot::SetupAxes(nullptr, nullptr, ImPlotAxisFlags_NoTickLabels, ImPlotAxisFlags_AutoFit);

        ImPlot::SetupAxisLimits(ImAxis_X1, 0, count, ImGuiCond_Always);
        ImPlot::SetupAxisLimits(ImAxis_Y1, 0, maxLatency * 1.1f, ImGuiCond_Always);

        ImPlot::PushStyleColor(ImPlotCol_Line, ImVec4(0.9f, 0.7f, 0.2f, 1.0f));
        ImPlot::PlotLine("Latency", latencyMs.data() + start, count);
        ImPlot::PopStyleColor();

        ImDrawList* draw = ImPlot::GetPlotDrawList();
        ImPlotRect limits = ImPlot::GetPlotLimits();
        ImVec2 tl = ImPlot::PlotToPixels(limits.X.Min, limits.Y.Max);
        ImVec2 tr = ImPlot::PlotToPixels(limits.X.Max, limits.Y.Max);
        draw->AddText(ImVec2(tl.x + 6, tl.y + 6), IM_COL32(200, 200, 200, 255), "Latency");

        if (ImPlot::IsPlotHovered())
        {
            ImPlotPoint p = ImPlot::GetPlotMousePos();
            int idx = start + (int)p.x;
            if (idx >= 0 && idx < n && std::isfinite(latencyMs[idx]))
            {
                ImGui::BeginTooltip();
                ImGui::Text("Latency: %.1f ms", latencyMs[idx]);
                ImGui::EndTooltip();
            }
        }

        ImPlot::EndPlot();
    }
}

void PlotJitter(const std::vector<float>& jitterMs, float graphHeight)
{
    if (jitterMs.empty())
        return;

    const int n = (int)jitterMs.size();
    const int window = 150;
    const int start = n > window ? n - window : 0;
    const int count = n - start;
    float maxJitter = 1.0f;
    for (int i = start; i < n; ++i)
        maxJitter = std::max(maxJitter, jitterMs[i]);

    if (ImPlot::BeginPlot("##Jitter (ms)", ImVec2(-1, graphHeight), ImPlotFlags_NoLegend | ImPlotFlags_NoMenus))
    {
        ImPlot::SetupAxes(nullptr, nullptr, ImPlotAxisFlags_NoTickLabels,ImPlotAxisFlags_AutoFit);

        ImPlot::SetupAxisLimits(ImAxis_X1, 0, count, ImGuiCond_Always);
		ImPlot::SetupAxisLimits(ImAxis_Y1, 0, maxJitter * 1.1f, ImGuiCond_Always);

        ImPlot::PushStyleColor(ImPlotCol_Line, ImVec4(0.9f, 0.7f, 0.2f, 1.0f));
        ImPlot::PlotLine("Jitter", jitterMs.data() + start, count);
        ImPlot::PopStyleColor();

        ImDrawList* draw = ImPlot::GetPlotDrawList();
        ImPlotRect limits = ImPlot::GetPlotLimits();
        ImVec2 tl = ImPlot::PlotToPixels(limits.X.Min, limits.Y.Max);
        ImVec2 tr = ImPlot::PlotToPixels(limits.X.Max, limits.Y.Max);
        draw->AddText(ImVec2(tl.x + 6, tl.y + 6), IM_COL32(200, 200, 200, 255), "Jitter");

        if (ImPlot::IsPlotHovered())
        {
            ImPlotPoint p = ImPlot::GetPlotMousePos();
            int idx = start + (int)p.x;
            if (idx >= 0 && idx < n && std::isfinite(jitterMs[idx]))
            {
                ImGui::BeginTooltip();
                ImGui::Text("Jitter: %.1f ms", jitterMs[idx]);
                ImGui::EndTooltip();
            }
        }

        ImPlot::EndPlot();
    }
}


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
    static double metricAccum = 0.0;

    if (IsCapturing()) {
        metricAccum += dt;
        if (metricAccum >= 0.5) {
            UpdateMetrics(metricAccum);
            metricAccum = 0.0;
        }
    }

    Metrics m = GetMetrics();

    int totalSeconds = (int)m.timeElapsed;
    int minutes = totalSeconds / 60;
    int seconds = totalSeconds % 60;

    ImGuiIO& io = ImGui::GetIO();
    if (io.DisplaySize.x <= 0.0f || io.DisplaySize.y <= 0.0f)
        return;
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(io.DisplaySize);

    ImGui::Begin("Dashboard", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse);

    // =====================================================
    // TOP BAR
    // =====================================================
    auto devices = GetAvailableDevices();
    static char filter[256] = "";

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
        if (selectedDevice >= 0 && ImGui::Button("Start")) {
            StartCapture(selectedDevice, filter);
            StartAppBandwidth();
        }
    }
    else {
        if (ImGui::Button("Stop")) {
            StopAppBandwidth();
            StopCapture();
        }
    }

    ImGui::SameLine();
    if (ImGui::Button("Save"))
    {
        std::string filename = ShowSaveFileDialog();

        if (!filename.empty())
        {
            g_showSaveMessage = true;

            std::thread([filename]()
                {
                    SavePcap(filename);
                    std::lock_guard<std::mutex> lock(g_mutex);
                }).detach();
        }
    }

    ImGui::SameLine();
    if (ImGui::Button("Ping")) {
        std::thread([] {
            g_ping.Start("8.8.8.8", 4);
            }).detach();
    }

    ImGui::SameLine();
    ImGui::Text("Network Latency: %.1f ms   ", g_ping.GetAverageLatency());
    ImGui::SameLine();
    ImGui::Text("Network Jitter: %.1f ms    ", g_ping.GetAverageJitter());
    ImGui::SameLine();
    ImGui::Text("Network Loss: %.1f %%  ", g_ping.GetPacketLoss());
    ImGui::Separator();

    // =============
    // FILTER
    // =============
    ImGui::Text("Capture Filter:");
    ImGui::SameLine();
    ImGui::InputText("##filter", filter, sizeof(filter));
    ImGui::SameLine();
    if (ImGui::Button("Apply Filter"))
    {
        ApplyFilter(filter);
    }
    ImGui::Separator();

    // ===========================
    // SUMMARY CARDS
    // ===========================
    ImGui::BeginChild("Summary", ImVec2(0,60), false);
    ImGui::Columns(7, nullptr, false);

    ImGui::Text("Total Packets\n%llu", m.totalPackets);
    ImGui::NextColumn();
    ImGui::Text("Bandwidth\n%s", FormatBytes(m.bps, Buf, sizeof(Buf)));
    ImGui::NextColumn();
    ImGui::Text("Packets/s\n%.1f", m.pps);
    ImGui::NextColumn();
    ImGui::Text("Total Data\n%s", FormatBytes(m.totalBytes, Buf, sizeof(Buf)));
	ImGui::NextColumn();
    ImGui::Text("Average Latency\n%.1f ms", m.averageLatency);
    ImGui::NextColumn();
    ImGui::Text("Average Jitter\n%.1f ms", m.averageJitter);
    ImGui::NextColumn();
    ImGui::Text("Packet Loss\n%.1f %%", m.packetLoss);
    ImGui::NextColumn();

    ImGui::Text("Capture Visibility\n%.1f %%", m.captureVisibility * 100.0);
    ImGui::NextColumn();
    ImGui::Text("NIC Throughput\n%s", FormatBytes(m.nicBps, Buf, sizeof(Buf)));
    ImGui::NextColumn();
    ImGui::Text("Link Speed\n%.0f MB/s", m.linkSpeedBps / 1e6);
    ImGui::NextColumn();
    ImGui::Text("Time elapsed\n%02d:%02d", minutes, seconds);
    ImGui::NextColumn();
    ImGui::Text("Capture Mode\n%s", GetSourceName());
    ImGui::NextColumn();

    ImGui::Columns(1);
    ImGui::EndChild();

    ImGui::Separator();

    // =====================================================
    // MAIN SPLIT
    // =====================================================
    float remainingHeight = ImGui::GetContentRegionAvail().y - 25;
    float packetListHeight = remainingHeight * 0.30f;
    float upperHeight = remainingHeight - packetListHeight;

    ImGui::BeginChild("Upper", ImVec2(0, upperHeight), false);
    ImGui::Columns(2, nullptr, true);
    ImGui::SetColumnWidth(0, ImGui::GetWindowWidth() * 0.60f);

    ImGui::TableSetColumnIndex(0);

    // -------------------------------------------------
    // LEFT COLUMN: 2x2 GRAPH GRID
    // -------------------------------------------------
    float graphHeight = upperHeight * 0.45f;

    if (ImGui::BeginTable("LeftGraphs", 2, ImGuiTableFlags_BordersInner | ImGuiTableFlags_Resizable))
    {
        ImGui::TableNextRow();

        // -------- Top-left: Total Bandwidth --------
        ImGui::TableSetColumnIndex(0);
        {
            auto upHistory = GetUpBpsHistory();
            auto downHistory = GetDownBpsHistory();

            PlotBandwidthStacked(upHistory,downHistory);
        }

        // -------- Top-right: Bandwidth by Protocol --------
        ImGui::TableSetColumnIndex(1);
        {
            PlotProtocolStacked(GetProtocolBandwidthHistory());
        }

        ImGui::TableNextRow();

        // -------- Bottom-left: Latency --------
        ImGui::TableSetColumnIndex(0);
        {
            PlotLatency(GetLatencyHistory(), graphHeight);
        }

        // -------- Bottom-right: Reserved --------
        ImGui::TableSetColumnIndex(1);
        {
            PlotJitter(GetJitterHistory(), graphHeight);
        }

        ImGui::EndTable();
    }

    ImGui::NextColumn();

    // -----------------------------------------------------
    // RIGHT COLUMN (Top Hosts + Flows)
    // -----------------------------------------------------
    {
        ImGui::Text("Top Hosts");
        auto hosts = GetTopHosts(6);
        ImGui::BeginTable("HostsTable", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg);
        ImGui::TableSetupColumn("Host");
        ImGui::TableSetupColumn("MB");
        ImGui::TableHeadersRow();

        for (auto& h : hosts)
        {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(h.first.c_str());
            ImGui::TableSetColumnIndex(1); ImGui::Text("%.2f", (h.second / 1024.0));
        }
        ImGui::EndTable();

        // Top Flows Table
        ImGui::Text("Top Flows");
        auto flows = GetTopFlows(6);
        ImGui::BeginTable("FlowsTable", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg);
        ImGui::TableSetupColumn("Src");
        ImGui::TableSetupColumn("Dst");
        ImGui::TableSetupColumn("MB");
        ImGui::TableHeadersRow();

        for (auto& f : flows)
        {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("%s:%d", f.key.srcIP.c_str(), f.key.srcPort);
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%s:%d", f.key.dstIP.c_str(), f.key.dstPort);
            ImGui::TableSetColumnIndex(2);
            ImGui::Text("%.2f", (f.stats.bytesUp + f.stats.bytesDown) / 1048576.0);
        }
        ImGui::EndTable();

        char buf[32];
        ImGui::Text("Top Applications");
        auto apps = GetTopApplications(6);

        ImGui::BeginTable("AppsTable", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg);

        ImGui::TableSetupColumn("Application");
        ImGui::TableSetupColumn("Total");
        ImGui::TableSetupColumn("MB/s");
        ImGui::TableHeadersRow();

        for (const auto& a : apps)
        {
            ImGui::TableNextRow();

            // App name
            ImGui::TableSetColumnIndex(0);
            ImGui::TextUnformatted(a.name.c_str());

            // Total used
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(FormatBytes(a.totalBytes, buf, sizeof(buf)));

            // Current rate
            ImGui::TableSetColumnIndex(2);
           
            ImGui::Text("%.2f", a.rateMB);
        }

        ImGui::EndTable();
            
    }

    ImGui::Columns(1);
    ImGui::EndChild();
    

	// Debug Console (disabled by default)
    /*
    ImGui::Separator();
    ImGui::Text("Debug Log");

    ImGui::BeginChild("DebugLog", ImVec2(0, 150), true);

    auto log = GetDebugLog1();
    auto log3 = GetDebugLog3();
    bool scrollToBottom =
        ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 1.0f;

    for (const auto& line : log) {
        ImGui::TextUnformatted(line.c_str());
    }

    // Auto-scroll only if user didn't scroll up
    if (scrollToBottom)
        ImGui::SetScrollHereY(1.0f);

    ImGui::EndChild();
    */
    ImGui::Separator();
    // =====================================================
    // PACKET LIST (FULL WIDTH)
    // =====================================================
    ImGui::Text("Recent Packets (Last 1000)");
    ImGui::BeginChild("Packets", ImVec2(0, packetListHeight), true, ImGuiWindowFlags_HorizontalScrollbar);
    bool scrollToBottom = ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 1.0f;

    auto packets = GetRecentPackets(1000);
    for (int i = 0; i < (int)packets.size(); i++) {
        const auto& p = packets[i];
        ImGui::PushID(i);

        std::string label = p.srcIP + ":" + std::to_string(p.srcPort) + " - " + p.dstIP + ":" + std::to_string(p.dstPort) + "  " + p.protocol;

        ImGui::Selectable(label.c_str());
        ImGui::PopID();
    }
    if (scrollToBottom)
        ImGui::SetScrollHereY(1.0f);
    ImGui::EndChild();
    ImGui::End();
}