// pcap_reader.cpp
#include "pcap_reader.hpp"
#include <fstream>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <arpa/inet.h>

namespace ipflow {

// PCAP 文件头结构 (24 bytes)
struct PcapFileHeader {
  uint32_t magic;           // 0xa1b2c3d4 或 0xd4c3b2a1
  uint16_t version_major;
  uint16_t version_minor;
  int32_t thiszone;
  uint32_t sigfigs;
  uint32_t snaplen;
  uint32_t linktype;
};

// PCAP 数据包头结构 (16 bytes)
struct PcapPacketHeader {
  uint32_t ts_sec;    // 时间戳秒
  uint32_t ts_usec;   // 时间戳微秒
  uint32_t caplen;    // 捕获的数据包长度
  uint32_t len;       // 实际数据包长度
};

// Ethernet 头结构 (14 bytes)
struct EthernetHeader {
  uint8_t dst_mac[6];
  uint8_t src_mac[6];
  uint16_t ether_type;
};

// IP 头结构 (最小 20 bytes)
struct IpHeader {
  uint8_t version_ihl;      // 版本(4位) + 头长度(4位)
  uint8_t tos;
  uint16_t total_length;
  uint16_t identification;
  uint16_t flags_fragment;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;
  uint32_t src_ip;
  uint32_t dst_ip;
};

// TCP 头结构 (最小 20 bytes)
struct TcpHeader {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seq;
  uint32_t ack;
  uint8_t data_offset_reserved;  // 数据偏移(4位) + 保留(4位)
  uint8_t flags;
  uint16_t window;
  uint16_t checksum;
  uint16_t urgent_ptr;
};

// UDP 头结构 (8 bytes)
struct UdpHeader {
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t length;
  uint16_t checksum;
};

// TCP 标志位
constexpr uint8_t TCP_FIN = 0x01;
constexpr uint8_t TCP_SYN = 0x02;
constexpr uint8_t TCP_RST = 0x04;
constexpr uint8_t TCP_ACK = 0x10;

void PcapReader::read(const std::string& path, const Callback& cb) const {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    throw std::runtime_error("Cannot open file: " + path);
  }

  // 读取 PCAP 文件头
  PcapFileHeader file_header;
  file.read(reinterpret_cast<char*>(&file_header), sizeof(file_header));
  if (!file || file.gcount() != sizeof(file_header)) {
    throw std::runtime_error("Cannot read pcap file header");
  }

  // 检查魔数（支持大小端）
  if (file_header.magic != 0xa1b2c3d4 && file_header.magic != 0xd4c3b2a1) {
    throw std::runtime_error("Invalid pcap file format (bad magic number)");
  }

  // 检查链路层类型 (1 = Ethernet)
  if (file_header.linktype != 1) {
    throw std::runtime_error("Only Ethernet link type is supported");
  }

  // 读取每个数据包
  while (file) {
    PcapPacketHeader packet_header;
    file.read(reinterpret_cast<char*>(&packet_header), sizeof(packet_header));
    if (file.gcount() != sizeof(packet_header)) {
      break;  // 文件结束
    }

    // 读取数据包数据
    std::vector<uint8_t> packet_data(packet_header.caplen);
    file.read(reinterpret_cast<char*>(packet_data.data()), packet_header.caplen);
    if (file.gcount() != static_cast<std::streamsize>(packet_header.caplen)) {
      throw std::runtime_error("Error reading packet data");
    }

    // 解析数据包
    PacketInfo info = {};
    info.ts = packet_header.ts_sec + packet_header.ts_usec / 1000000.0;

    // 解析 Ethernet 头
    if (packet_data.size() < sizeof(EthernetHeader)) continue;

    const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(packet_data.data());
    uint16_t ether_type = ntohs(eth->ether_type);

    // 只处理 IPv4 (0x0800)
    if (ether_type != 0x0800) continue;

    // 解析 IP 头
    size_t offset = sizeof(EthernetHeader);
    if (packet_data.size() < offset + sizeof(IpHeader)) continue;

    const IpHeader* ip = reinterpret_cast<const IpHeader*>(packet_data.data() + offset);
    
    // 检查 IP 版本
    uint8_t ip_version = (ip->version_ihl >> 4) & 0x0F;
    if (ip_version != 4) continue;

    // 计算 IP 头长度
    uint8_t ip_header_len = (ip->version_ihl & 0x0F) * 4;
    if (ip_header_len < 20) continue;

    // 填充 IP 信息
    info.src_ip = ntohl(ip->src_ip);
    info.dst_ip = ntohl(ip->dst_ip);
    info.proto = ip->protocol;
    info.len = ntohs(ip->total_length);

    // 初始化 TCP 标志位
    info.tcp_syn = false;
    info.tcp_ack = false;
    info.tcp_rst = false;
    info.tcp_fin = false;

    offset += ip_header_len;

    // 处理传输层协议
    if (ip->protocol == 6) {  // TCP
      if (packet_data.size() < offset + sizeof(TcpHeader)) continue;

      const TcpHeader* tcp = reinterpret_cast<const TcpHeader*>(packet_data.data() + offset);
      info.src_port = ntohs(tcp->src_port);
      info.dst_port = ntohs(tcp->dst_port);

      // 解析 TCP 标志位
      uint8_t flags = tcp->flags;
      info.tcp_syn = (flags & TCP_SYN) != 0;
      info.tcp_ack = (flags & TCP_ACK) != 0;
      info.tcp_rst = (flags & TCP_RST) != 0;
      info.tcp_fin = (flags & TCP_FIN) != 0;
    }
    else if (ip->protocol == 17) {  // UDP
      if (packet_data.size() < offset + sizeof(UdpHeader)) continue;

      const UdpHeader* udp = reinterpret_cast<const UdpHeader*>(packet_data.data() + offset);
      info.src_port = ntohs(udp->src_port);
      info.dst_port = ntohs(udp->dst_port);
    }
    else {
      // 其他协议（如 ICMP）
      info.src_port = 0;
      info.dst_port = 0;
    }

    // 调用回调函数
    cb(info);
  }
}

}  // namespace ipflow