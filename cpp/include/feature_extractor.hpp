#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <unordered_set>
#include <vector>
#include "pcap_reader.hpp"

namespace ipflow {

// Protocol statistics: packet count and byte count
struct ProtocolStats {
    uint32_t packet_count;
    uint64_t byte_count;

    ProtocolStats() : packet_count(0), byte_count(0) {}
};

// Features for a single IP address
struct IPFeatures {
    uint32_t ip;                // IP address (host byte order)
    double timestamp;           // Window end time

    // Protocol statistics: <protocol_number, <packet_count, total_bytes>>
    std::map<uint8_t, ProtocolStats> protocol_stats;

    // Overall statistics
    uint32_t total_packets;
    uint64_t total_bytes;

    // TCP flag statistics
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
    // Set target IP list (only statistics for these IPs will be collected)
    void setTargetIPs(const std::unordered_set<uint32_t>& target_ips);

    // Extract features from packet list
    // Returns features for each IP (only includes IPs in target_ips)
    std::vector<IPFeatures> extractFeatures(
        double window_end_time,
        const std::vector<PacketInfo>& packets
    );

    // IP address conversion utility functions
    static uint32_t ipStringToUint32(const std::string& ip_str);
    static std::string uint32ToIpString(uint32_t ip);

private:
    std::unordered_set<uint32_t> target_ips_;

    // Check if packet contains target IP
    bool matchesTargetIP(const PacketInfo& packet) const;
};

}  // namespace ipflow
