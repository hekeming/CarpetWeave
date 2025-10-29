#include "sliding_window.hpp"
#include <algorithm>

namespace ipflow {

SlidingWindow::SlidingWindow(double window_size, double slide_step)
    : window_size_(window_size),
      slide_step_(slide_step),
      current_window_start_(0.0),
      first_packet_ts_(0.0),
      first_packet_received_(false) {
}

void SlidingWindow::setCallback(const WindowCallback& cb) {
    callback_ = cb;
}

void SlidingWindow::addPacket(const PacketInfo& packet) {
    // 记录第一个包的时间戳
    if (!first_packet_received_) {
        first_packet_ts_ = packet.ts;
        current_window_start_ = first_packet_ts_;
        first_packet_received_ = true;
    }

    // 添加数据包到队列
    packets_.push_back(packet);

    // 检查是否需要滑动窗口
    double current_ts = packet.ts;
    double next_window_start = current_window_start_ + slide_step_;

    while (current_ts >= next_window_start + window_size_) {
        // 处理当前窗口
        double window_end = current_window_start_ + window_size_;
        processWindow(current_window_start_, window_end);

        // 滑动窗口
        current_window_start_ = next_window_start;
        next_window_start += slide_step_;

        // 清理过期数据包（早于当前窗口起始时间的包）
        removeExpiredPackets(current_window_start_);
    }
}

void SlidingWindow::finish() {
    if (!first_packet_received_) {
        return;  // 没有收到任何包
    }

    // 处理所有剩余的窗口
    if (!packets_.empty()) {
        double last_packet_ts = packets_.back().ts;
        double next_window_start = current_window_start_ + slide_step_;

        // 处理当前窗口到最后一个包之间的所有窗口
        while (next_window_start <= last_packet_ts) {
            double window_end = current_window_start_ + window_size_;
            processWindow(current_window_start_, window_end);

            current_window_start_ = next_window_start;
            next_window_start += slide_step_;
            removeExpiredPackets(current_window_start_);
        }

        // 处理最后一个窗口
        double final_window_end = current_window_start_ + window_size_;
        processWindow(current_window_start_, final_window_end);
    }
}

void SlidingWindow::processWindow(double window_start, double window_end) {
    if (!callback_) {
        return;  // 没有设置回调函数
    }

    // 收集窗口内的所有数据包
    WindowFeatures features;
    features.window_start = window_start;
    features.window_end = window_end;

    for (const auto& packet : packets_) {
        // 只包含在窗口时间范围内的包
        if (packet.ts >= window_start && packet.ts < window_end) {
            features.ip_packets[packet.dst_ip].push_back(packet);
        }
    }

    // 调用回调函数
    callback_(features);
}

void SlidingWindow::removeExpiredPackets(double threshold_ts) {
    // 移除所有时间戳早于threshold_ts的包
    while (!packets_.empty() && packets_.front().ts < threshold_ts) {
        packets_.pop_front();
    }
}

}  // namespace ipflow
