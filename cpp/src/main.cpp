#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>
#include "csv_writer.hpp"
#include "feature_extractor.hpp"
#include "pcap_reader.hpp"
#include "sliding_window.hpp"

// 简单的JSON解析（手动实现，避免依赖外部库）
#include <sstream>
#include <cctype>

namespace {

// 简单的JSON解析器（只支持我们需要的格式）
class SimpleJsonParser {
public:
    explicit SimpleJsonParser(const std::string& json_str) : json_(json_str), pos_(0) {}

    std::vector<std::string> getStringArray(const std::string& key) {
        std::vector<std::string> result;
        size_t key_pos = json_.find("\"" + key + "\"");
        if (key_pos == std::string::npos) return result;

        size_t array_start = json_.find("[", key_pos);
        size_t array_end = json_.find("]", array_start);
        if (array_start == std::string::npos || array_end == std::string::npos) return result;

        std::string array_content = json_.substr(array_start + 1, array_end - array_start - 1);

        // 解析数组中的字符串
        size_t pos = 0;
        while (pos < array_content.length()) {
            size_t quote1 = array_content.find("\"", pos);
            if (quote1 == std::string::npos) break;
            size_t quote2 = array_content.find("\"", quote1 + 1);
            if (quote2 == std::string::npos) break;

            std::string value = array_content.substr(quote1 + 1, quote2 - quote1 - 1);
            result.push_back(value);
            pos = quote2 + 1;
        }

        return result;
    }

    double getNumber(const std::string& key) {
        size_t key_pos = json_.find("\"" + key + "\"");
        if (key_pos == std::string::npos) return 0.0;

        size_t colon_pos = json_.find(":", key_pos);
        if (colon_pos == std::string::npos) return 0.0;

        // 跳过空格
        size_t num_start = colon_pos + 1;
        while (num_start < json_.length() && std::isspace(json_[num_start])) {
            num_start++;
        }

        // 提取数字
        size_t num_end = num_start;
        while (num_end < json_.length() &&
               (std::isdigit(json_[num_end]) || json_[num_end] == '.' || json_[num_end] == '-')) {
            num_end++;
        }

        std::string num_str = json_.substr(num_start, num_end - num_start);
        return std::stod(num_str);
    }

    std::string getString(const std::string& key) {
        size_t key_pos = json_.find("\"" + key + "\"");
        if (key_pos == std::string::npos) return "";

        size_t colon_pos = json_.find(":", key_pos);
        if (colon_pos == std::string::npos) return "";

        size_t quote1 = json_.find("\"", colon_pos);
        if (quote1 == std::string::npos) return "";

        size_t quote2 = json_.find("\"", quote1 + 1);
        if (quote2 == std::string::npos) return "";

        return json_.substr(quote1 + 1, quote2 - quote1 - 1);
    }

private:
    std::string json_;
    size_t pos_;
};

std::string readFile(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + path);
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

struct Config {
    std::vector<std::string> target_ips;
    double window_size;
    double slide_step;
    std::string output_file;
};

Config loadConfig(const std::string& config_path) {
    std::string json_content = readFile(config_path);
    SimpleJsonParser parser(json_content);

    Config config;
    config.target_ips = parser.getStringArray("target_ips");
    config.window_size = parser.getNumber("window_size");
    config.slide_step = parser.getNumber("slide_step");
    config.output_file = parser.getString("output_file");

    return config;
}

}  // anonymous namespace

int main(int argc, char* argv[]) {
    try {
        if (argc != 3) {
            std::cerr << "Usage: " << argv[0] << " <pcap_file> <config_json>\n";
            return 1;
        }

        std::string pcap_path = argv[1];
        std::string config_path = argv[2];

        // 加载配置
        std::cout << "Loading configuration from " << config_path << "\n";
        Config config = loadConfig(config_path);

        // 打印配置信息
        std::cout << "Target IPs: ";
        for (size_t i = 0; i < config.target_ips.size(); ++i) {
            std::cout << config.target_ips[i];
            if (i < config.target_ips.size() - 1) std::cout << ", ";
        }
        std::cout << "\n";
        std::cout << "Window size: " << config.window_size << "s, "
                  << "Slide step: " << config.slide_step << "s\n";
        std::cout << "Output file: " << config.output_file << "\n";

        // 转换目标IP为uint32_t
        std::unordered_set<uint32_t> target_ips_uint;
        for (const auto& ip_str : config.target_ips) {
            try {
                uint32_t ip = ipflow::FeatureExtractor::ipStringToUint32(ip_str);
                target_ips_uint.insert(ip);
            } catch (const std::exception& e) {
                std::cerr << "Warning: Invalid IP address '" << ip_str << "': " << e.what() << "\n";
            }
        }

        // 初始化组件
        ipflow::PcapReader reader;
        ipflow::FeatureExtractor extractor;
        extractor.setTargetIPs(target_ips_uint);

        ipflow::SlidingWindow window(config.window_size, config.slide_step);
        ipflow::CSVWriter csv_writer(config.output_file);

        // 统计变量
        uint64_t total_packets = 0;
        uint64_t filtered_packets = 0;

        // 设置滑动窗口的回调函数
        window.setCallback([&extractor, &csv_writer](const ipflow::WindowFeatures& win_feat) {
            // 为每个IP提取特征
            std::vector<ipflow::IPFeatures> all_features;

            for (const auto& ip_packets_pair : win_feat.ip_packets) {
                auto features = extractor.extractFeatures(
                    win_feat.window_end,
                    ip_packets_pair.second
                );
                all_features.insert(all_features.end(), features.begin(), features.end());
            }

            if (!all_features.empty()) {
                csv_writer.writeFeatures(all_features);
                std::cout << "Window [" << win_feat.window_start << " - "
                          << win_feat.window_end << "] processed, "
                          << all_features.size() << " unique IPs\n";
            }
        });

        // 处理pcap文件
        std::cout << "Processing " << pcap_path << "...\n";

        reader.read(pcap_path, [&](const ipflow::PacketInfo& packet) {
            total_packets++;

            // 检查是否匹配目标IP
            bool matches = target_ips_uint.empty() ||
                          target_ips_uint.count(packet.src_ip) > 0 ||
                          target_ips_uint.count(packet.dst_ip) > 0;

            if (matches) {
                filtered_packets++;
                window.addPacket(packet);
            }

            // 每处理10万个包打印一次进度
            if (total_packets % 100000 == 0) {
                std::cout << "Processed " << total_packets << " packets...\n";
            }
        });

        // 完成处理
        window.finish();

        std::cout << "\nDone! Total packets processed: " << total_packets << "\n";
        std::cout << "Filtered packets (matching target IPs): " << filtered_packets << "\n";
        std::cout << "Results written to: " << config.output_file << "\n";

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
