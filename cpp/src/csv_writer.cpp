#include "csv_writer.hpp"
#include <iomanip>
#include <stdexcept>

namespace ipflow {

CSVWriter::CSVWriter(const std::string& filename)
    : filename_(filename), header_written_(false) {
    file_.open(filename);
    if (!file_.is_open()) {
        throw std::runtime_error("Cannot open output file: " + filename);
    }
}

CSVWriter::~CSVWriter() {
    close();
}

void CSVWriter::writeHeader() {
    if (header_written_) {
        return;
    }

    // 写入CSV头部
    // 格式：timestamp,ip,total_packets,total_bytes,tcp_packets,tcp_bytes,udp_packets,udp_bytes,
    //       icmp_packets,icmp_bytes,other_packets,other_bytes,tcp_syn,tcp_ack,tcp_rst,tcp_fin
    file_ << "timestamp,ip,total_packets,total_bytes,"
          << "tcp_packets,tcp_bytes,udp_packets,udp_bytes,"
          << "icmp_packets,icmp_bytes,other_packets,other_bytes,"
          << "tcp_syn,tcp_ack,tcp_rst,tcp_fin\n";

    header_written_ = true;
}

void CSVWriter::writeFeatures(const std::vector<IPFeatures>& features) {
    if (!header_written_) {
        writeHeader();
    }

    for (const auto& feat : features) {
        // 时间戳和IP
        file_ << std::fixed << std::setprecision(6) << feat.timestamp << ","
              << FeatureExtractor::uint32ToIpString(feat.ip) << ","
              << feat.total_packets << ","
              << feat.total_bytes;

        // 提取各协议的统计数据
        // TCP (protocol 6)
        auto tcp_it = feat.protocol_stats.find(6);
        uint32_t tcp_packets = (tcp_it != feat.protocol_stats.end()) ? tcp_it->second.packet_count : 0;
        uint64_t tcp_bytes = (tcp_it != feat.protocol_stats.end()) ? tcp_it->second.byte_count : 0;

        // UDP (protocol 17)
        auto udp_it = feat.protocol_stats.find(17);
        uint32_t udp_packets = (udp_it != feat.protocol_stats.end()) ? udp_it->second.packet_count : 0;
        uint64_t udp_bytes = (udp_it != feat.protocol_stats.end()) ? udp_it->second.byte_count : 0;

        // ICMP (protocol 1)
        auto icmp_it = feat.protocol_stats.find(1);
        uint32_t icmp_packets = (icmp_it != feat.protocol_stats.end()) ? icmp_it->second.packet_count : 0;
        uint64_t icmp_bytes = (icmp_it != feat.protocol_stats.end()) ? icmp_it->second.byte_count : 0;

        // 其他协议（除了TCP、UDP、ICMP之外）
        uint32_t other_packets = 0;
        uint64_t other_bytes = 0;
        for (const auto& proto_stat : feat.protocol_stats) {
            uint8_t proto = proto_stat.first;
            if (proto != 6 && proto != 17 && proto != 1) {  // 不是TCP、UDP、ICMP
                other_packets += proto_stat.second.packet_count;
                other_bytes += proto_stat.second.byte_count;
            }
        }

        // 写入协议统计
        file_ << "," << tcp_packets << "," << tcp_bytes
              << "," << udp_packets << "," << udp_bytes
              << "," << icmp_packets << "," << icmp_bytes
              << "," << other_packets << "," << other_bytes;

        // TCP标志
        file_ << "," << feat.tcp_syn_count
              << "," << feat.tcp_ack_count
              << "," << feat.tcp_rst_count
              << "," << feat.tcp_fin_count;

        file_ << "\n";
    }

    file_.flush();
}

void CSVWriter::close() {
    if (file_.is_open()) {
        file_.close();
    }
}

}  // namespace ipflow
