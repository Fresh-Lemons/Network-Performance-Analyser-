// SnifferDX_Pie.cpp
// Single-file DirectX11 + ImGui sniffer with time-based graphs, packet list, filters, PCAP save, and protocol pie chart.
// Requirements: ImGui core + backends/imgui_impl_win32.cpp + imgui_impl_dx11.cpp in project.
// Link: wpcap.lib Packet.lib ws2_32.lib d3d11.lib
#ifndef PI_F
#define PI_F 3.14159265358979323846f
#endif

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <d3d11.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <pcap.h>

#include <thread>
#include <atomic>
#include <mutex>
#include <vector>
#include <string>
#include <chrono>
#include <cmath>
#include <iostream>
#include <cstdint>
#include <algorithm>

#include "imgui.h"
#include "backends/imgui_impl_win32.h"
#include "backends/imgui_impl_dx11.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")

// ---------------- DirectX Globals ----------------
ID3D11Device* g_pd3dDevice = nullptr;
ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
IDXGISwapChain* g_pSwapChain = nullptr;
ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

// ---------------- Win32 Forward ----------------
extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);

// ---------------- Metrics ----------------
std::atomic<uint64_t> g_totalPackets{ 0 };
std::atomic<uint64_t> g_totalBytes{ 0 };
std::atomic<double>   g_currentBps{ 0 };
std::atomic<double>   g_currentPps{ 0 };
std::atomic<double>   g_lastLatencyMs{ 0 };
std::atomic<double>   g_jitterMs{ 0 };

std::mutex g_graphMutex;
std::vector<float> g_bpsHistory(300, 0.0f);
std::vector<float> g_ppsHistory(300, 0.0f);

// ---------------- Packet Capture ----------------
struct DeviceInfo { std::string name; std::string description; };
std::vector<DeviceInfo> g_devices;
pcap_t* g_handle = nullptr;
std::atomic<bool> g_running{ false };
std::mutex g_captureMutex;
std::thread g_captureThread;

// ---------------- Packet List ----------------
struct PacketInfo {
    std::string srcIP;
    std::string dstIP;
    uint16_t srcPort;
    uint16_t dstPort;
    std::string protocol;
    std::vector<uint8_t> rawData; // for saving to PCAP
    uint32_t rawLen;
    timeval ts;
};

std::vector<PacketInfo> g_packetList;
std::mutex g_packetMutex;
static int g_selectedPacket = -1;

// ---------------- Utility ----------------
static inline std::string ipToString(uint32_t ip_le) {
    // ip_le is little-endian from captured bytes, convert to dotted string
    uint8_t b0 = (ip_le >> 0) & 0xFF;
    uint8_t b1 = (ip_le >> 8) & 0xFF;
    uint8_t b2 = (ip_le >> 16) & 0xFF;
    uint8_t b3 = (ip_le >> 24) & 0xFF;
    return std::to_string(b0) + "." + std::to_string(b1) + "." + std::to_string(b2) + "." + std::to_string(b3);
}

// ---------------- Packet Handler ----------------
void PacketHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* data)
{
    static thread_local std::chrono::high_resolution_clock::time_point lastTime;
    auto now = std::chrono::high_resolution_clock::now();

    g_totalPackets.fetch_add(1);
    g_totalBytes.fetch_add(header->len);

    if (lastTime.time_since_epoch().count() != 0)
    {
        double diff = std::chrono::duration<double, std::milli>(now - lastTime).count();
        g_lastLatencyMs.store(diff);

        // atomic += equivalent
        double oldJitter = g_jitterMs.load();
        double newJitter;
        do {
            newJitter = oldJitter + std::abs(g_lastLatencyMs.load() - diff) * 0.1;
        } while (!g_jitterMs.compare_exchange_weak(oldJitter, newJitter));
    }
    lastTime = now;

    // parse IPv4 + TCP/UDP minimally
    if (header->caplen < 14 + 20) return;
    uint16_t ethType = (data[12] << 8) | data[13];
    if (ethType != 0x0800) return; // only IPv4

    const u_char* ip = data + 14;
    uint8_t ihl = (ip[0] & 0x0F) * 4;
    if (ihl < 20) return;
    uint8_t ipProto = ip[9];
    uint32_t srcIP = *(uint32_t*)(ip + 12);
    uint32_t dstIP = *(uint32_t*)(ip + 16);

    uint16_t srcPort = 0, dstPort = 0;
    std::string protoStr = "OTHER";

    if (ipProto == 6 && header->caplen >= 14 + ihl + 4) { // TCP
        const u_char* l4 = ip + ihl;
        srcPort = ntohs(*(uint16_t*)(l4 + 0));
        dstPort = ntohs(*(uint16_t*)(l4 + 2));
        protoStr = "TCP";
    }
    else if (ipProto == 17 && header->caplen >= 14 + ihl + 4) { // UDP
        const u_char* l4 = ip + ihl;
        srcPort = ntohs(*(uint16_t*)(l4 + 0));
        dstPort = ntohs(*(uint16_t*)(l4 + 2));
        protoStr = "UDP";
    }
    else if (ipProto == 1) {
        protoStr = "ICMP";
    }

    PacketInfo pkt;
    pkt.srcIP = ipToString(srcIP);
    pkt.dstIP = ipToString(dstIP);
    pkt.srcPort = srcPort;
    pkt.dstPort = dstPort;
    pkt.protocol = protoStr;
    pkt.rawLen = header->caplen;
    pkt.rawData.assign(data, data + header->caplen);
    pkt.ts = header->ts;

    {
        std::lock_guard<std::mutex> lock(g_packetMutex);
        g_packetList.push_back(std::move(pkt));
        if (g_packetList.size() > 10000) // keep a reasonable full history cap
            g_packetList.erase(g_packetList.begin());
    }
}

// ---------------- Capture Thread ----------------
void CaptureThread(pcap_t* handle)
{
    uint64_t lastBytes = g_totalBytes.load();
    uint64_t lastPackets = g_totalPackets.load();
    auto lastTime = std::chrono::steady_clock::now();

    while (g_running)
    {
        // pcap_dispatch will call PacketHandler for captured packets and return
        int ret = pcap_dispatch(handle, 0, PacketHandler, nullptr);
        if (ret < 0) {
            // error or break
            break;
        }

        // small sleep to avoid burning CPU if no packets
        std::this_thread::sleep_for(std::chrono::milliseconds(1));

        // metrics update moved to GUI loop (time-based) - keep only minimal here
    }

    pcap_close(handle);
}

// ---------------- Save PCAP ----------------
bool SavePcapToFile(const char* filename)
{
    std::vector<PacketInfo> copy;
    {
        std::lock_guard<std::mutex> lock(g_packetMutex);
        copy = g_packetList; // copy
    }
    if (copy.empty()) return false;

    // Use pcap_open_dead to create a dumper even if not currently capturing
    pcap_t* dead = pcap_open_dead(DLT_EN10MB, 65535);
    if (!dead) return false;
    pcap_dumper_t* dumper = pcap_dump_open(dead, filename);
    if (!dumper) {
        pcap_close(dead);
        return false;
    }

    for (const auto& pkt : copy) {
        struct pcap_pkthdr hdr;
        hdr.caplen = pkt.rawLen;
        hdr.len = pkt.rawLen;
        hdr.ts = pkt.ts;
        pcap_dump((u_char*)dumper, &hdr, pkt.rawData.data());
    }
    pcap_dump_close(dumper);
    pcap_close(dead);
    return true;
}

// ---------------- Simple pie drawing (sector using convex poly) ----------------
void DrawPie(ImDrawList* dl, const ImVec2& center, float radius, float a0, float a1, ImU32 color, int num_segments = 64)
{
    // Build fan from center to arc points between a0..a1
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

// ---------------- DirectX Helpers ----------------
bool CreateDeviceD3D(HWND hWnd)
{
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[1] = { D3D_FEATURE_LEVEL_11_0 };

    if (D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
        0, featureLevelArray, 1, D3D11_SDK_VERSION, &sd, &g_pSwapChain,
        &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext) != S_OK)
        return false;
    return true;
}

void CleanupDeviceD3D()
{
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

void CreateRenderTarget()
{
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

void CleanupRenderTarget()
{
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

// ---------------- WinMain ----------------
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int)
{
    // Enumerate adapters
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs = nullptr;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        MessageBoxA(0, errbuf, "pcap_findallds failed", MB_ICONERROR);
        return 1;
    }
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        g_devices.push_back({ d->name ? d->name : "", d->description ? d->description : d->name ? d->name : "" });
    }
    pcap_freealldevs(alldevs);

    // Create Win32 window
    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0, 0, GetModuleHandle(NULL),
                      nullptr, nullptr, nullptr, nullptr, TEXT("SnifferWinClass"), nullptr };
    RegisterClassEx(&wc);
    HWND hwnd = CreateWindow(wc.lpszClassName, TEXT("Network Sniffer Dashboard"),
        WS_OVERLAPPEDWINDOW, 100, 100, 1280, 800,
        nullptr, nullptr, wc.hInstance, nullptr);

    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        UnregisterClass(wc.lpszClassName, wc.hInstance);
        return 1;
    }
    CreateRenderTarget();
    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    // Setup ImGui
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    ImGui::StyleColorsDark();
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    // UI state
    static int selectedDevice = -1;
    char filterIP[64] = "";
    int filterPort = 0;
    char filterProto[8] = "";

    auto lastGraphUpdate = std::chrono::steady_clock::now();
    uint64_t lastBytes = g_totalBytes.load();
    uint64_t lastPackets = g_totalPackets.load();

    MSG msg{};
    while (msg.message != WM_QUIT)
    {
        if (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            continue;
        }

        // Time-based graph update (every 200ms)
        auto now = std::chrono::steady_clock::now();
        double dtGraph = std::chrono::duration<double>(now - lastGraphUpdate).count();
        if (dtGraph >= 0.2) {
            uint64_t bytes = g_totalBytes.load();
            uint64_t packets = g_totalPackets.load();

            double bps = double(bytes - lastBytes) / dtGraph;
            double pps = double(packets - lastPackets) / dtGraph;

            lastBytes = bytes;
            lastPackets = packets;
            lastGraphUpdate = now;

            // push history (thread-safe)
            {
                std::lock_guard<std::mutex> lock(g_graphMutex);
                g_bpsHistory.erase(g_bpsHistory.begin());
                g_bpsHistory.push_back((float)bps);
                g_ppsHistory.erase(g_ppsHistory.begin());
                g_ppsHistory.push_back((float)pps);
            }

            g_currentBps.store(bps);
            g_currentPps.store(pps);
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        // Full-window dashboard
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);
        ImGui::Begin("Dashboard", nullptr,
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoCollapse);

        // Top controls
        if (ImGui::BeginCombo("Interface", selectedDevice >= 0 ? g_devices[selectedDevice].description.c_str() : "Select...")) {
            for (int i = 0; i < (int)g_devices.size(); ++i) {
                bool sel = (selectedDevice == i);
                if (ImGui::Selectable(g_devices[i].description.c_str(), sel)) selectedDevice = i;
                if (sel) ImGui::SetItemDefaultFocus();
            }
            ImGui::EndCombo();
        }

        if (!g_running) {
            ImGui::SameLine();
            if (selectedDevice >= 0 && ImGui::Button("Start Capture")) {
                std::lock_guard<std::mutex> lock(g_captureMutex);
                g_handle = pcap_open_live(g_devices[selectedDevice].name.c_str(), 65536, 1, 100, errbuf);
                if (!g_handle) {
                    MessageBoxA(0, errbuf, "Failed to open adapter", MB_ICONERROR);
                }
                else {
                    g_running = true;
                    g_captureThread = std::thread(CaptureThread, g_handle);
                }
            }
        }
        else {
            ImGui::SameLine();
            if (ImGui::Button("Stop Capture")) {
                g_running = false;
                if (g_captureThread.joinable()) g_captureThread.join();
            }
        }

        ImGui::SameLine();
        if (ImGui::Button("Save PCAP")) {
            bool ok = SavePcapToFile("capture.pcap");
            if (!ok) MessageBoxA(0, "Failed to save capture.pcap", "Error", MB_ICONERROR);
        }

        ImGui::Separator();

        // Metrics
        ImGui::Text("Packets: %llu", g_totalPackets.load());
        ImGui::Text("Bytes: %llu", g_totalBytes.load());
        ImGui::Text("Bandwidth: %.2f KB/s", g_currentBps.load() / 1024.0);
        ImGui::Text("PPS: %.2f", g_currentPps.load());
        ImGui::Text("Last Latency: %.3f ms", g_lastLatencyMs.load());
        ImGui::Text("Jitter: %.3f ms", g_jitterMs.load());

        ImGui::Separator();

        // Filters
        ImGui::InputText("Filter IP", filterIP, sizeof(filterIP));
        ImGui::InputInt("Filter Port", &filterPort);
        ImGui::InputText("Filter Proto", filterProto, sizeof(filterProto));

        ImGui::Separator();

        // Layout: two columns
        ImGui::Columns(2, nullptr, true);
        float colWidth = ImGui::GetColumnWidth();
        float colHeight = ImGui::GetContentRegionAvail().y;

        // -- Left: Graphs + Pie chart (use copies for thread-safety)
        std::vector<float> bpsCopy, ppsCopy;
        {
            std::lock_guard<std::mutex> lock(g_graphMutex);
            bpsCopy = g_bpsHistory;
            ppsCopy = g_ppsHistory;
        }

        ImGui::Text("Bandwidth");
        ImGui::PlotLines("##Bandwidth", bpsCopy.data(), (int)bpsCopy.size(), 0, nullptr, 0.0f, FLT_MAX, ImVec2(0, colHeight / 4.0f));
        ImGui::Text("PPS");
        ImGui::PlotLines("##PPS", ppsCopy.data(), (int)ppsCopy.size(), 0, nullptr, 0.0f, FLT_MAX, ImVec2(0, colHeight / 4.0f));

        // Protocol distribution (pie)
        // compute counts
        float tcp = 0, udp = 0, icmp = 0, other = 0;
        {
            std::lock_guard<std::mutex> lock(g_packetMutex);
            for (auto& p : g_packetList) {
                if (p.protocol == "TCP") tcp += 1.0f;
                else if (p.protocol == "UDP") udp += 1.0f;
                else if (p.protocol == "ICMP") icmp += 1.0f;
                else other += 1.0f;
            }
        }
        float total = tcp + udp + icmp + other;
        ImGui::Separator();
        ImGui::Text("Protocol Distribution");
        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImVec2 pieCenter = ImGui::GetCursorScreenPos();
        float pieRadius = std::min(colWidth, colHeight / 4.0f) * 0.25f + 50.0f;
        // leave some space for a legend
        ImGui::Dummy(ImVec2(0.0f, pieRadius * 2.0f + 10.0f));
        float a = -PI_F * 0.5f;
        if (total > 0.0f) {
            auto drawSlice = [&](float count, ImU32 col) {
                if (count <= 0.0f) return;
                float ang = (count / total) * (2.0f * (float)PI_F);
                DrawPie(dl, ImVec2(pieCenter.x + pieRadius, pieCenter.y + pieRadius), pieRadius, a, a + ang, col, 64);
                a += ang;
                };
            drawSlice(tcp, ImColor(0.2f, 0.8f, 0.2f, 1.0f));
            drawSlice(udp, ImColor(0.2f, 0.4f, 0.9f, 1.0f));
            drawSlice(icmp, ImColor(1.0f, 0.6f, 0.2f, 1.0f));
            drawSlice(other, ImColor(0.8f, 0.8f, 0.8f, 1.0f));
        }
        else {
            // draw empty circle
            dl->AddCircle(ImVec2(pieCenter.x + pieRadius, pieCenter.y + pieRadius), pieRadius, IM_COL32(120, 120, 120, 255), 64, 2.0f);
        }
        // draw legend
        ImGui::SameLine();
        ImGui::BeginGroup();
        ImGui::Text("TCP: %.0f", tcp);
        ImGui::Text("UDP: %.0f", udp);
        ImGui::Text("ICMP: %.0f", icmp);
        ImGui::Text("Other: %.0f", other);
        ImGui::EndGroup();

        ImGui::NextColumn();

        // -- Right: Packet list (show last 30, but keep full history)
        ImGui::Text("Packet List (Last 30)");
        float childHeight = colHeight / 1.8f;
        ImGui::BeginChild("PacketListChild", ImVec2(0, childHeight), true, ImGuiWindowFlags_HorizontalScrollbar);

        // copy packet list for rendering
        std::vector<PacketInfo> packetCopy;
        {
            std::lock_guard<std::mutex> lock(g_packetMutex);
            packetCopy = g_packetList;
        }

        int totalPackets = (int)packetCopy.size();

        // detect if user is scrolling (if scroll not at bottom)
        float scrollY = ImGui::GetScrollY();
        float scrollMax = ImGui::GetScrollMaxY();
        bool userScrolling = (scrollY < scrollMax - 1e-3f); // if not at bottom consider user scrolling

        for (int i = 0; i < totalPackets; ++i) {
            const auto& pkt = packetCopy[i];
            ImGui::PushID(i); // unique id
            ImVec4 col = ImVec4(1, 1, 1, 1);
            if (pkt.protocol == "TCP") col = ImVec4(0.4f, 1.0f, 0.4f, 1.0f);
            else if (pkt.protocol == "UDP") col = ImVec4(0.4f, 0.4f, 1.0f, 1.0f);
            else if (pkt.protocol == "ICMP") col = ImVec4(1.0f, 0.6f, 0.4f, 1.0f);

            ImGui::PushStyleColor(ImGuiCol_Text, col);
            std::string label = pkt.srcIP + ":" + std::to_string(pkt.srcPort) + " -> " + pkt.dstIP + ":" + std::to_string(pkt.dstPort) + " " + pkt.protocol;
            if (ImGui::Selectable(label.c_str(), g_selectedPacket == i)) {
                g_selectedPacket = i;
            }
            ImGui::PopStyleColor();
            ImGui::PopID();
        }

        if (!userScrolling) {
            ImGui::SetScrollHereY(1.0f); // auto-scroll only if user not scrolling
        }
        ImGui::EndChild();

        // Selected details
        if (g_selectedPacket >= 0 && g_selectedPacket < packetCopy.size()) {
            const auto& pkt = packetCopy[g_selectedPacket];
            ImGui::Text("Selected Packet:");
            ImGui::Text("Src: %s:%u", pkt.srcIP.c_str(), pkt.srcPort);
            ImGui::Text("Dst: %s:%u", pkt.dstIP.c_str(), pkt.dstPort);
            ImGui::Text("Proto: %s", pkt.protocol.c_str());
            ImGui::Text("Len: %u", pkt.rawLen);
            ImGui::Separator();
            // show hex dump (first 64 bytes)
            ImGui::Text("Hex (first 64 bytes):");
            int show = (int)std::min<size_t>(pkt.rawData.size(), 64);
            char buf[64 * 3 + 1]; buf[0] = 0;
            for (int i = 0; i < show; i++) {
                char tmp[4];
                sprintf_s(tmp, sizeof(tmp), "%02X ", pkt.rawData[i]);
                strcat_s(buf, tmp);
            }
            ImGui::TextWrapped("%s", buf);
        }

        ImGui::Columns(1);
        ImGui::End(); // Dashboard

        // Rendering
        ImGui::Render();
        float clear_col[4] = { 0.08f, 0.08f, 0.09f, 1.0f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_col);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(1, 0);
    }

    // Shutdown: stop capture thread and join
    g_running = false;
    if (g_captureThread.joinable()) g_captureThread.join();

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClass(wc.lpszClassName, wc.hInstance);

    return 0;
}

// ---------------- Win32 WndProc ----------------
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (g_pd3dDevice != nullptr && wParam != SIZE_MINIMIZED)
        {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, LOWORD(lParam), HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }
}
