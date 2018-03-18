extern "C" {
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
}
#undef min
#undef max

#include "udp.h"

#include <iostream>
#include <iomanip>
#include <utility>
#include <memory>
#include <thread>
#include <vector>

namespace {

using sec = std::chrono::duration<double, std::micro>;

// The netbench server responds to this port.
constexpr uint16_t kNetbenchPort = 8001;

constexpr uint32_t kMagic = 0x6e626368; // 'nbch'

struct nbench_req {
  uint32_t magic;
  int nports;
  int measure_sec;
};

struct nbench_resp {
  uint32_t magic;
  int nports;
  uint16_t ports[];
};

void ServerWorker(int fd) {
  unsigned char buf[rt::UdpConn::kMaxPayloadSize];

  while (true) {
    // Receive a network response.
    ssize_t ret = read(fd, &buf, sizeof(buf));
    if (ret <= 0 || ret > static_cast<ssize_t>(sizeof(buf))) {
      if (ret == 0) break;
      printf("udp read failed, ret = %ld\n", ret);
      exit(1);
    }

    // Send a network request.
    ssize_t sret = write(fd, &buf, ret);
    if (sret != ret) {
      if (ret == -ESHUTDOWN) break;
      printf("udp write failed, ret = %ld\n", ret);
      exit(1);
    }
  }

  close(fd);
}

void ServerHandler(void *arg) {
  struct sockaddr_in addr;
  int fd;

  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    printf("socket() failed %d\n", -errno);
    exit(1);
  }

  memset((char *)&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(kNetbenchPort);

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    printf("bind() failed %d\n", -errno);
    exit(1);
  }

  while (true) {
    nbench_req req;
    sockaddr_in caddr;
    socklen_t caddr_len = sizeof(caddr);
    ssize_t ret = recvfrom(fd, &req, sizeof(req), 0, (struct sockaddr *)&caddr, &caddr_len);
    if (ret != sizeof(req) || req.magic != kMagic) continue;

    auto t = std::thread([=]{
      printf("got connection %x:%d, %d seconds, %d ports\n",
             addr.sin_addr.s_addr, addr.sin_port,
             req.measure_sec, req.nports);

      union {
        nbench_resp resp;
        char buf[rt::UdpConn::kMaxPayloadSize];
      };
      resp.magic = kMagic;
      resp.nports = req.nports;

      // Create the worker threads.
      std::vector<int> conns;
      for (int i = 0; i < req.nports; ++i) {
        int fdin;
        if ((fdin = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
          printf("socket() failed %d\n", -errno);
          exit(1);
        }

        struct sockaddr_in laddr;
        memset((char *)&laddr, 0, sizeof(laddr));
        laddr.sin_family = AF_INET;
        laddr.sin_addr.s_addr = htonl(INADDR_ANY);
        laddr.sin_port = htons(0);

        if (bind(fdin, (struct sockaddr *)&laddr, sizeof(laddr)) < 0) {
          printf("bind() failed %d\n", -errno);
          exit(1);
        }

        socklen_t addr_len = sizeof(addr);
        if (getsockname(fdin, (struct sockaddr*)&laddr, &addr_len) < 0) {
          printf("getsockname() failed %d\n", -errno);
          exit(1);
        }

        if (connect(fdin, (struct sockaddr *)&caddr, sizeof(caddr)) < 0) {
          printf("connect() failed %d\n", -errno);
          exit(1);
        }

	resp.ports[i] = ntohs(laddr.sin_port);
        std::thread(ServerWorker, fdin).detach();
        conns.emplace_back(fdin);
      }

      // Send the port numbers to the client.
      ssize_t len = sizeof(nbench_resp) + sizeof(uint16_t) * req.nports;
      if (len > static_cast<ssize_t>(rt::UdpConn::kMaxPayloadSize))
        printf("too big\n");
      ssize_t ret = sendto(fd, &resp, len, 0, (struct sockaddr *)&caddr, sizeof(caddr));
      if (ret != len) {
        printf("udp write failed, ret = %ld\n", ret);
      }

      // Sleep for one extra second to give the experiment time to finish.
      sleep(req.measure_sec + 1);

      // Shutdown the workers and wait for them to exit.
      for (int i = 0; i < req.nports; i++)
        shutdown(conns[i], SHUT_RDWR);
    });
    t.detach();
  }
}

} // anonymous namespace

int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::cerr << "usage: [cmd] ..." << std::endl;
    return -EINVAL;
  }

  std::string cmd = argv[1];
  if (cmd.compare("server") == 0) {
    ServerHandler(nullptr);
    return 0;
  } else {
    return 1;
  }
}
