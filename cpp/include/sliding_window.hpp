#pragma once

#include <deque>
#include <functional>
#include <unordered_map>
#include "pcap_reader.hpp"

namespace ipflow {

// 窗口特征数据
struct WindowFeatures {
    double window_start;
    double window_end;
    std::unordered_map<uint32_t, std::vector<PacketInfo>> ip_packets;  // IP -> 该IP的包列表
};

class SlidingWindow {
public:
    using WindowCallback = std::function<void(const WindowFeatures&)>;

    SlidingWindow(double window_size, double slide_step);

    // 添加数据包到窗口
    void addPacket(const PacketInfo& packet);

    // 设置窗口完成回调
    void setCallback(const WindowCallback& cb);

    // 完成处理（处理最后的窗口）
    void finish();

private:
    double window_size_;      // 窗口大小（秒）
    double slide_step_;       // 滑动步长（秒）
    double current_window_start_;  // 当前窗口起始时间
    double first_packet_ts_;  // 第一个包的时间戳
    bool first_packet_received_;

    std::deque<PacketInfo> packets_;  // 所有在窗口范围内的包
    WindowCallback callback_;

    // 处理当前窗口（生成特征并回调）
    void processWindow(double window_start, double window_end);

    // 清理过期数据包
    void removeExpiredPackets(double threshold_ts);
};

}  // namespace ipflow
