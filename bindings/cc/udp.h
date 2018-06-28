// udp.h - support for UDP networking

#pragma once

extern "C" {
#include <base/stddef.h>
#include <runtime/udp.h>
}

namespace rt {

class UdpConn {
 public:
  // The maximum size of a UDP packet.
  static constexpr size_t kMaxPayloadSize = UDP_MAX_PAYLOAD;

  ~UdpConn() { udp_close(c_); }

  // Creates a UDP connection between a local and remote address.
  static UdpConn *Dial(netaddr laddr, netaddr raddr) {
    udpconn_t *c;
    int ret = udp_dial(laddr, raddr, &c);
    if (ret) return nullptr;
    return new UdpConn(c);
  }

  // Creates a UDP connection that receives all packets on a local port.
  static UdpConn *Listen(netaddr laddr) {
    udpconn_t *c;
    int ret = udp_listen(laddr, &c);
    if (ret) return nullptr;
    return new UdpConn(c);
  }

  // Gets the local UDP address.
  netaddr LocalAddr() const { return udp_local_addr(c_); }
  // Gets the remote UDP address.
  netaddr RemoteAddr() const { return udp_remote_addr(c_); }

  // Adjusts the length of buffer limits.
  int SetBuffers(int read_mbufs, int write_mbufs) {
    return udp_set_buffers(c_, read_mbufs, write_mbufs);
  }

  // Reads a packet and gets from remote address.
  ssize_t ReadFrom(void *buf, size_t len, netaddr *raddr) {
    return udp_read_from(c_, buf, len, raddr);
  }

  // Writes a packet and sets to remote address.
  ssize_t WriteTo(const void *buf, size_t len, const netaddr *raddr) {
    return udp_write_to(c_, buf, len, raddr);
  }

  // Reads a packet.
  ssize_t Read(void *buf, size_t len) {
    return udp_read(c_, buf, len);
  }

  // Writes a packet.
  ssize_t Write(const void *buf, size_t len) {
    return udp_write(c_, buf, len);
  }

  // Shutdown the socket (no more receives).
  void Shutdown() {
    udp_shutdown(c_);
  }

 private:
  UdpConn(udpconn_t *c) : c_(c) { }

  // disable move and copy.
  UdpConn(const UdpConn&) = delete;
  UdpConn& operator=(const UdpConn&) = delete;

  udpconn_t *c_;
};

} // namespace rt
