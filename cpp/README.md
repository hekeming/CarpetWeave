# IPv4 Flow Feature Extractor

一个基于滑动窗口的pcap包长特征提取器，用于分析网络流量并生成特征矩阵。

## 项目简介

本项目实现了一个高性能的网络流量特征提取工具，能够从pcap文件中提取IPv4流量的统计特征。主要功能包括：

- 基于时间的滑动窗口分析
- 按协议分类的包长直方图统计（TCP/UDP/ICMP）
- 支持按IP地址过滤
- CSV格式输出，便于后续分析

## 项目结构

```
cpp/
├── include/               # 头文件
│   ├── pcap_reader.hpp   # pcap文件读取器
│   ├── sliding_window.hpp # 滑动窗口实现
│   ├── feature_extractor.hpp # 特征提取器
│   └── csv_writer.hpp    # CSV输出
├── src/                  # 源文件
│   ├── pcap_reader.cpp
│   ├── sliding_window.cpp
│   ├── feature_extractor.cpp
│   ├── csv_writer.cpp
│   └── main.cpp
├── CMakeLists.txt        # CMake配置
└── README.md             # 本文件
```

## 依赖要求

### 编译器
- C++17 或更高版本
- GCC 7+ / Clang 5+ / MSVC 2017+

### 构建工具
- CMake 3.10+


## 编译方法

### Linux / macOS

```bash
# 创建构建目录
mkdir build
cd build

# 配置项目
cmake ..

# 编译
make

# 可执行文件生成在 build/ipflow_extractor
```

### 编译选项

```bash
# Debug模式编译
cmake -DCMAKE_BUILD_TYPE=Debug ..
make

# Release模式编译（默认，启用优化）
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

## 使用方法

### 基本用法

```bash
./ipflow_extractor <pcap_file> <config_json>
```

### 参数说明

- `<pcap_file>`: 输入的pcap文件路径
- `<config_json>`: 配置文件路径（JSON格式）

### 示例

```bash
cd build
./ipflow_extractor ../data/seq_10.pcap ../data/stats.json
```

## 配置文件说明

配置文件为JSON格式，包含以下字段：

```json
{
  "target_ips": [
    "192.168.1.100",
    "192.168.1.101"
  ],
  "window_size": 60,
  "slide_step": 30,
  "output_file": "features.csv"
}
```

### 配置项详解

- **target_ips**: 字符串数组，指定要统计的目标IP地址列表
  - 只有源IP或目的IP在此列表中的数据包会被统计
  - 如果为空数组，则统计所有IP

- **window_size**: 数值，滑动窗口大小（单位：秒）
  - 定义每个时间窗口的长度

- **slide_step**: 数值，窗口滑动步长（单位：秒）
  - 定义窗口每次移动的时间间隔
  - 如果 slide_step < window_size，窗口会重叠

- **output_file**: 字符串，输出CSV文件名
  - 相对于当前工作目录的路径

## 输出格式说明

输出为CSV格式文件，每行代表一个时间窗口中某个IP的特征。

## 使用示例

### 示例1：分析特定IP的流量

```bash
# 1. 创建配置文件
cat > config.json <<EOF
{
  "target_ips": ["192.168.1.100"],
  "window_size": 60,
  "slide_step": 30,
  "output_file": "ip_features.csv"
}
EOF

# 2. 运行分析
./ipflow_extractor capture.pcap config.json

# 3. 查看结果
head -n 5 ip_features.csv
```

### 示例2：全流量分析

```bash
# 配置空的target_ips表示分析所有IP
cat > config.json <<EOF
{
  "target_ips": [],
  "window_size": 120,
  "slide_step": 60,
  "output_file": "all_features.csv"
}
EOF

./ipflow_extractor capture.pcap config.json

