#include "feature_extractor.hpp"
#include <arpa/inet.h>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

namespace ipflow {

// Convert IP address string to uint32_t (host byte order)
uint32_t FeatureExtractor::ipStringToUint32(const std::string& ip_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) {
        throw std::runtime_error("Invalid IP address: " + ip_str);
    }
    return ntohl(addr.s_addr);  // Convert to host byte order
}

// Convert uint32_t to IP address string (input is in host byte order)
std::string FeatureExtractor::uint32ToIpString(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);  // Convert to network byte order
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
        return true;  // If no target IPs specified, accept all packets
    }
    return target_ips_.count(packet.src_ip) > 0 || target_ips_.count(packet.dst_ip) > 0;
}

std::vector<IPFeatures> FeatureExtractor::extractFeatures(
    double window_end_time,
    const std::vector<PacketInfo>& packets
) {
    // Maintain features for each IP
    std::unordered_map<uint32_t, IPFeatures> ip_features_map;

    for (const auto& packet : packets) {
        // Only process packets matching target IPs
        if (!matchesTargetIP(packet)) {
            continue;
        }

        // Determine which IP(s) this packet should be attributed to
        // If src_ip is in target_ips, attribute to src_ip
        // If dst_ip is in target_ips, attribute to dst_ip
        // If both are in target_ips, count for both
        std::vector<uint32_t> ips_to_update;

        if (target_ips_.empty() || target_ips_.count(packet.src_ip) > 0) {
            ips_to_update.push_back(packet.src_ip);
        }
        if (target_ips_.count(packet.dst_ip) > 0 && packet.dst_ip != packet.src_ip) {
            ips_to_update.push_back(packet.dst_ip);
        }

        for (uint32_t ip : ips_to_update) {
            // Get or create features for this IP
            auto& features = ip_features_map[ip];
            if (features.ip == 0) {  // First time creation
                features.ip = ip;
                features.timestamp = window_end_time;
            }

            // Update overall statistics
            features.total_packets++;
            features.total_bytes += packet.len;

            // Update protocol statistics
            uint8_t proto = packet.proto;
            features.protocol_stats[proto].packet_count++;
            features.protocol_stats[proto].byte_count += packet.len;

            // Update TCP flags
            if (packet.proto == 6) {  // TCP
                if (packet.tcp_syn) features.tcp_syn_count++;
                if (packet.tcp_ack) features.tcp_ack_count++;
                if (packet.tcp_rst) features.tcp_rst_count++;
                if (packet.tcp_fin) features.tcp_fin_count++;
            }
        }
    }

    // Convert to vector and return
    std::vector<IPFeatures> result;
    result.reserve(ip_features_map.size());
    for (const auto& pair : ip_features_map) {
        result.push_back(pair.second);
    }

    return result;
}

}  // namespace ipflow
