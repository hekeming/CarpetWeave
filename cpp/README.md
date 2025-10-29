# IPv4 Flow Feature Extractor

一个基于滑动窗口的pcap包长特征提取器，用于分析网络流量并生成特征矩阵。

## 项目简介

本项目实现了一个高性能的网络流量特征提取工具，能够从pcap文件中提取IPv4流量的统计特征。主要功能包括：

- 基于时间的滑动窗口分析
- 按协议分类的包长直方图统计（TCP/UDP/ICMP）
- TCP标志位统计（SYN/ACK/RST/FIN）
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

### 系统依赖
无额外依赖（使用内置的pcap文件解析器，无需libpcap）

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

### CSV列结构

| 列名 | 说明 | 类型 |
|------|------|------|
| timestamp | 窗口结束时间戳（秒） | double |
| ip | IP地址（点分十进制） | string |
| total_packets | 总包数 | uint64 |
| total_bytes | 总字节数 | uint64 |
| tcp_len_0-64 | TCP包长区间 [0-64] 字节的包数 | uint64 |
| tcp_len_65-128 | TCP包长区间 [65-128] 字节的包数 | uint64 |
| tcp_len_129-256 | TCP包长区间 [129-256] 字节的包数 | uint64 |
| tcp_len_257-512 | TCP包长区间 [257-512] 字节的包数 | uint64 |
| tcp_len_513-1024 | TCP包长区间 [513-1024] 字节的包数 | uint64 |
| tcp_len_1025-1518 | TCP包长区间 [1025-1518] 字节的包数 | uint64 |
| tcp_len_1519+ | TCP包长区间 [1519+] 字节的包数 | uint64 |
| udp_len_0-64 | UDP包长区间 [0-64] 字节的包数 | uint64 |
| udp_len_65-128 | UDP包长区间 [65-128] 字节的包数 | uint64 |
| ... | UDP其他区间（同TCP） | uint64 |
| icmp_len_0-64 | ICMP包长区间 [0-64] 字节的包数 | uint64 |
| icmp_len_65-128 | ICMP包长区间 [65-128] 字节的包数 | uint64 |
| ... | ICMP其他区间（同TCP） | uint64 |
| tcp_syn | TCP SYN标志包数 | uint64 |
| tcp_ack | TCP ACK标志包数 | uint64 |
| tcp_rst | TCP RST标志包数 | uint64 |
| tcp_fin | TCP FIN标志包数 | uint64 |

### 输出示例

```csv
timestamp,ip,total_packets,total_bytes,tcp_len_0-64,tcp_len_65-128,...,tcp_syn,tcp_ack,tcp_rst,tcp_fin
60.000000,192.168.1.100,150,45000,20,30,40,25,15,10,10,5,10,15,8,12,5,3,0,0,0,0,0,0,0,10,120,2,5
60.000000,192.168.1.101,80,12000,10,15,20,10,8,7,10,2,3,5,3,4,2,1,0,0,0,0,0,0,0,5,60,1,2
```

## 特征说明

### 包长直方图

将数据包长度分为7个区间进行统计：
- 0-64 字节：通常是小包（ACK、控制包等）
- 65-128 字节：中小型包
- 129-256 字节：中型包
- 257-512 字节：中大型包
- 513-1024 字节：大包
- 1025-1518 字节：接近MTU的大包
- 1519+ 字节：超大包（巨型帧）

每个协议（TCP/UDP/ICMP）都有独立的直方图。

### TCP标志统计

统计TCP包中各标志位的出现次数：
- **SYN**: 连接建立请求
- **ACK**: 确认应答
- **RST**: 连接重置
- **FIN**: 连接终止

## 错误处理

程序会处理以下错误情况：

1. **文件不存在**: 如果pcap文件或配置文件不存在，程序会报错退出
2. **格式错误**: 如果pcap文件格式不正确，会抛出异常
3. **无效IP地址**: 配置文件中的无效IP会被警告并跳过
4. **输出文件创建失败**: 如果无法创建输出CSV文件，程序会报错

## 性能说明

- **处理速度**: 能够高效处理百万级别的数据包
- **内存管理**: 使用滑动窗口自动清理过期数据包，内存占用稳定
- **进度显示**: 每处理10万个包输出一次进度信息

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
```

## 常见问题

### Q: 如何选择合适的window_size和slide_step？

A:
- **window_size**: 取决于分析需求
  - 短期行为分析：10-60秒
  - 中期趋势分析：60-300秒
  - 长期模式分析：300秒以上

- **slide_step**: 取决于分析粒度
  - slide_step = window_size: 无重叠，适合快速统计
  - slide_step < window_size: 有重叠，适合平滑分析

### Q: target_ips列表过滤的逻辑是什么？

A: 如果数据包的源IP或目的IP在target_ips列表中，该包就会被统计。同时，该包会为列表中出现的每个IP（src或dst）各生成一条统计记录。

### Q: 输出的timestamp含义是什么？

A: timestamp表示时间窗口的结束时间，单位是秒（相对于pcap文件中的第一个包）。

### Q: 支持哪些链路层类型？

A: 目前只支持以太网（Ethernet）链路层类型。

## 许可证

本项目供学习和研究使用。

## 作者

IPv4 Flow Feature Extractor Development Team

## 更新日志

### Version 1.0.0 (2024)
- 初始版本发布
- 实现基本的特征提取功能
- 支持滑动窗口分析
- CSV格式输出
