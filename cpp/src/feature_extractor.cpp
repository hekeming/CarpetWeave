#include "feature_extractor.hpp"
#include <arpa/inet.h>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

namespace ipflow {

// IP地址字符串转uint32_t（主机字节序）
uint32_t FeatureExtractor::ipStringToUint32(const std::string& ip_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) {
        throw std::runtime_error("Invalid IP address: " + ip_str);
    }
    return ntohl(addr.s_addr);  // 转换为主机字节序
}

// uint32_t转IP地址字符串（输入为主机字节序）
std::string FeatureExtractor::uint32ToIpString(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);  // 转换为网络字节序
    char str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &addr, str, INET_ADDRSTRLEN) == nullptr) {
        throw std::runtime_error("Failed to convert IP to string");
    }
    return std::string(str);
}

void FeatureExtractor::setTargetIPs(const std::unordered_set<uint32_t>& target_ips) {
    target_ips_ = target_ips;
}

bool FeatureExtractor::matchesTargetIP(const PacketInfo& packet) const {
    if (target_ips_.empty()) {
        return true;  // 如果没有指定目标IP，则接受所有包
    }
    return target_ips_.count(packet.src_ip) > 0 || target_ips_.count(packet.dst_ip) > 0;
}

size_t FeatureExtractor::getLengthBin(uint16_t len) {
    if (len <= 64) return 0;
    if (len <= 128) return 1;
    if (len <= 256) return 2;
    if (len <= 512) return 3;
    if (len <= 1024) return 4;
    if (len <= 1518) return 5;
    return 6;  // 1519+
}

Protocol FeatureExtractor::getProtocol(uint8_t proto_num) {
    switch (proto_num) {
        case 6:   return Protocol::TCP;
        case 17:  return Protocol::UDP;
        case 1:   return Protocol::ICMP;
        default:  return Protocol::ICMP;  // 将其他协议归类为ICMP
    }
}

std::vector<IPFeatures> FeatureExtractor::extractFeatures(
    double window_end_time,
    const std::vector<PacketInfo>& packets
) {
    // 为每个IP维护特征
    std::unordered_map<uint32_t, IPFeatures> ip_features_map;

    for (const auto& packet : packets) {
        // 只处理匹配目标IP的包
        if (!matchesTargetIP(packet)) {
            continue;
        }

        // 判断这个包应该归属于哪个IP的统计
        // 如果src_ip在target_ips中，归属于src_ip
        // 如果dst_ip在target_ips中，归属于dst_ip
        // 如果两者都在，则两个都统计
        std::vector<uint32_t> ips_to_update;

        if (target_ips_.empty() || target_ips_.count(packet.src_ip) > 0) {
            ips_to_update.push_back(packet.src_ip);
        }
        if (target_ips_.count(packet.dst_ip) > 0 && packet.dst_ip != packet.src_ip) {
            ips_to_update.push_back(packet.dst_ip);
        }

        for (uint32_t ip : ips_to_update) {
            // 获取或创建该IP的特征
            auto& features = ip_features_map[ip];
            if (features.ip == 0) {  // 首次创建
                features.ip = ip;
                features.timestamp = window_end_time;
            }

            // 更新统计
            features.total_packets++;
            features.total_bytes += packet.len;

            // 更新包长直方图
            Protocol proto = getProtocol(packet.proto);
            size_t bin = getLengthBin(packet.len);
            features.length_hist[static_cast<size_t>(proto)][bin]++;

            // 更新TCP标志
            if (packet.proto == 6) {  // TCP
                if (packet.tcp_syn) features.tcp_syn_count++;
                if (packet.tcp_ack) features.tcp_ack_count++;
                if (packet.tcp_rst) features.tcp_rst_count++;
                if (packet.tcp_fin) features.tcp_fin_count++;
            }
        }
    }

    // 转换为vector返回
    std::vector<IPFeatures> result;
    result.reserve(ip_features_map.size());
    for (const auto& pair : ip_features_map) {
        result.push_back(pair.second);
    }

    return result;
}

}  // namespace ipflow
