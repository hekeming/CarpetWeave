#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>
#include "pcap_reader.hpp"

namespace ipflow {

// 包长直方图的bin数量（7个区间）
constexpr size_t NUM_LENGTH_BINS = 7;

// 协议类型
enum class Protocol {
    TCP = 0,
    UDP = 1,
    ICMP = 2,
    COUNT = 3
};

// 单个IP的特征
struct IPFeatures {
    double timestamp;           // 窗口结束时间
    uint32_t ip;                // IP地址（网络字节序）
    uint64_t total_packets;     // 总包数
    uint64_t total_bytes;       // 总字节数

    // 包长直方图：[协议][bin]
    // 协议：TCP(0), UDP(1), ICMP(2)
    // bin: 0-64, 65-128, 129-256, 257-512, 513-1024, 1025-1518, 1519+
    std::array<std::array<uint64_t, NUM_LENGTH_BINS>, 3> length_hist;

    // TCP标志统计
    uint64_t tcp_syn_count;
    uint64_t tcp_ack_count;
    uint64_t tcp_rst_count;
    uint64_t tcp_fin_count;

    IPFeatures()
        : timestamp(0), ip(0), total_packets(0), total_bytes(0),
          tcp_syn_count(0), tcp_ack_count(0), tcp_rst_count(0), tcp_fin_count(0) {
        for (auto& proto_hist : length_hist) {
            proto_hist.fill(0);
        }
    }
};

class FeatureExtractor {
public:
    // 设置目标IP列表（只统计这些IP）
    void setTargetIPs(const std::unordered_set<uint32_t>& target_ips);

    // 从数据包列表提取特征
    // 返回每个IP的特征（只包含target_ips中的IP）
    std::vector<IPFeatures> extractFeatures(
        double window_end_time,
        const std::vector<PacketInfo>& packets
    );

    // IP地址转换工具函数
    static uint32_t ipStringToUint32(const std::string& ip_str);
    static std::string uint32ToIpString(uint32_t ip);

private:
    std::unordered_set<uint32_t> target_ips_;

    // 判断数据包是否包含目标IP
    bool matchesTargetIP(const PacketInfo& packet) const;

    // 获取包长对应的bin索引（0-6）
    static size_t getLengthBin(uint16_t len);

    // 获取协议类型
    static Protocol getProtocol(uint8_t proto_num);
};

}  // namespace ipflow
