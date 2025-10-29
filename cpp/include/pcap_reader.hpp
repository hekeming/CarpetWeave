#pragma once

#include <cstdint>
#include <functional>
#include <string>

namespace ipflow {

struct PacketInfo {
  double ts;
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t len;
  uint8_t proto;
  bool tcp_syn;
  bool tcp_ack;
  bool tcp_rst;
  bool tcp_fin;
};

class PcapReader {
 public:
  using Callback = std::function<void(const PacketInfo&)>;

  void read(const std::string& path, const Callback& cb) const;
};

}  // namespace ipflow
