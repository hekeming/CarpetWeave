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
    file_ << "timestamp,ip,total_packets,total_bytes";

    // TCP 包长直方图
    file_ << ",tcp_len_0-64,tcp_len_65-128,tcp_len_129-256,tcp_len_257-512,"
          << "tcp_len_513-1024,tcp_len_1025-1518,tcp_len_1519+";

    // UDP 包长直方图
    file_ << ",udp_len_0-64,udp_len_65-128,udp_len_129-256,udp_len_257-512,"
          << "udp_len_513-1024,udp_len_1025-1518,udp_len_1519+";

    // ICMP 包长直方图
    file_ << ",icmp_len_0-64,icmp_len_65-128,icmp_len_129-256,icmp_len_257-512,"
          << "icmp_len_513-1024,icmp_len_1025-1518,icmp_len_1519+";

    // TCP 标志
    file_ << ",tcp_syn,tcp_ack,tcp_rst,tcp_fin";

    file_ << "\n";
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

        // TCP 包长直方图（7个bin）
        for (size_t i = 0; i < NUM_LENGTH_BINS; ++i) {
            file_ << "," << feat.length_hist[static_cast<size_t>(Protocol::TCP)][i];
        }

        // UDP 包长直方图（7个bin）
        for (size_t i = 0; i < NUM_LENGTH_BINS; ++i) {
            file_ << "," << feat.length_hist[static_cast<size_t>(Protocol::UDP)][i];
        }

        // ICMP 包长直方图（7个bin）
        for (size_t i = 0; i < NUM_LENGTH_BINS; ++i) {
            file_ << "," << feat.length_hist[static_cast<size_t>(Protocol::ICMP)][i];
        }

        // TCP 标志
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
