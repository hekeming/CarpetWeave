#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <unordered_set>
#include <vector>
#include "pcap_reader.hpp"

namespace ipflow {

// 协议统计：包数和字节数
struct ProtocolStats {
    uint32_t packet_count;
    uint64_t byte_count;

    ProtocolStats() : packet_count(0), byte_count(0) {}
};

// 单个IP的特征
struct IPFeatures {
    uint32_t ip;                // IP地址（主机字节序）
    double timestamp;           // 窗口结束时间

    // 协议统计：<协议号, <包数, 总字节数>>
    std::map<uint8_t, ProtocolStats> protocol_stats;

    // 总体统计
    uint32_t total_packets;
    uint64_t total_bytes;

    // TCP标志统计
    uint32_t tcp_syn_count;
    uint32_t tcp_ack_count;
    uint32_t tcp_rst_count;
    uint32_t tcp_fin_count;

    IPFeatures()
        : ip(0), timestamp(0), total_packets(0), total_bytes(0),
          tcp_syn_count(0), tcp_ack_count(0), tcp_rst_count(0), tcp_fin_count(0) {}
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
};

}  // namespace ipflow
