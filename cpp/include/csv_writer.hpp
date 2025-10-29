#pragma once

#include <fstream>
#include <string>
#include <vector>
#include "feature_extractor.hpp"

namespace ipflow {

class CSVWriter {
public:
    explicit CSVWriter(const std::string& filename);
    ~CSVWriter();

    // 写入CSV头部
    void writeHeader();

    // 写入特征数据（可以是多个IP的特征）
    void writeFeatures(const std::vector<IPFeatures>& features);

    // 关闭文件
    void close();

private:
    std::ofstream file_;
    std::string filename_;
    bool header_written_;
};

}  // namespace ipflow
