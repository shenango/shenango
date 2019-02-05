extern "C" {
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#include <base/stddef.h>
#include <base/byteorder.h>
#include <asm/ops.h>
}
#undef min
#undef max

#include "net.h"
#include "fake_worker.h"

#include <iostream>
#include <iomanip>
#include <utility>
#include <memory>
#include <thread>
#include <vector>
#include <fstream>
#include <string>
#include <sstream>

namespace {

using sec = std::chrono::duration<double, std::micro>;
constexpr uint64_t kNetbenchPort = 8001;

// Reads exactly @len bytes from the TCP stream.
ssize_t ReadFull(int fd, void *buf, size_t len) {
  char *pos = reinterpret_cast<char*>(buf);
  size_t n = 0;
  while (n < len) {
    ssize_t ret = read(fd, pos + n, len - n);
    if (ret <= 0) return ret;
    n += ret;
  }
  assert(n == len);
  return n;
}

// Writes exactly @len bytes to the TCP stream.
ssize_t WriteFull(int fd, const void *buf, size_t len) {
  const char *pos = reinterpret_cast<const char*>(buf);
  size_t n = 0;
  while (n < len) {
    ssize_t ret = write(fd, pos + n, len - n);
    if (ret < 0) return ret;
    assert(ret > 0);
    n += ret;
  }
  assert(n == len);
  return n;
}

constexpr uint64_t kUptimePort = 8002;
constexpr uint64_t kUptimeMagic = 0xDEADBEEF;
struct uptime {
  uint64_t idle;
  uint64_t busy;
};

void UptimeWorker(int fd) {
  while (true) {
    // Receive an uptime request.
    uint64_t magic;
    ssize_t ret = ReadFull(fd, &magic, sizeof(magic));
    if (ret != static_cast<ssize_t>(sizeof(magic))) {
      if (ret == 0 || ret == -ECONNRESET) break;
      printf("read failed, ret = %ld\n", ret);
      break;
    }

    // Check for the right magic value.
    if (ntoh64(magic) != kUptimeMagic) break;

    // Calculate the current uptime.
    std::ifstream file("/proc/stat");
    std::string line;
    std::getline(file, line);
    std::istringstream ss(line);
    std::string tmp;
    uint64_t user, nice, system, idle, iowait, irq, softirq, steal, guest,
             guest_nice;
    ss >> tmp >> user >> nice >> system >> idle >> iowait >> irq >> softirq
       >> steal >> guest >> guest_nice;
    uptime u = {hton64(idle + iowait),
                hton64(user + nice + system + irq + softirq + steal)};

    // Send an uptime response.
    ssize_t sret = WriteFull(fd, &u, sizeof(u));
    if (sret != sizeof(u)) {
      if (sret == -EPIPE || sret == -ECONNRESET) break;
      printf("write failed, ret = %ld\n", sret);
      break;
    }
  }

  close(fd);
}

void UptimeServer() {
  struct sockaddr_in addr;
  int fd, childfd;
  int optval;

  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("socket() failed %d\n", -errno);
    exit(1);
  }

  optval = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
	         (const void *)&optval, sizeof(int)) < 0) {
    printf("setsockopt() failed %d\n", -errno);
    exit(1);
  }

  memset((char *)&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(kUptimePort);

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    printf("bind() failed %d\n", -errno);
    exit(1);
  }

  if (listen(fd, SOMAXCONN) < 0) {
    printf("listen failed %d\n", -errno);
    exit(1);
  }

  while (true) {
    childfd = accept(fd, NULL, 0);
    if (childfd == -1) {
      printf("accept() failed %d\n", -errno);
      exit(1);
    }

    std::thread([=] { UptimeWorker(childfd); }).detach();
  }
}

void ServerWorker(int fd) {
  struct payload {
    uint64_t work_iterations;
    uint64_t index;
    uint64_t tsc_end;
    uint32_t cpu;
  } p;

  std::unique_ptr<FakeWorker> w(FakeWorkerFactory("stridedmem:3200:64"));
  if (unlikely(w == nullptr)) exit(1);

  while (true) {
    // Receive a network response.
    ssize_t ret = ReadFull(fd, &p, sizeof(p));
    if (ret != static_cast<ssize_t>(sizeof(p))) {
      if (ret == 0 || ret == -ECONNRESET) break;
      printf("read failed, ret = %ld\n", ret);
      break;
    }

    // Perform fake work if requested.
    uint64_t workn = ntoh64(p.work_iterations);
    if (workn != 0) w->Work(workn);  // 82.0
    p.tsc_end = hton64(rdtscp(&p.cpu));
    p.cpu = hton32(p.cpu);

    // Send a network request.
    ssize_t sret = WriteFull(fd, &p, ret);
    if (sret != ret) {
      if (ret == -EPIPE || sret == -ECONNRESET) break;
      printf("write failed, ret = %ld\n", ret);
      break;
    }
  }

  close(fd);
}

void ServerHandler(void *arg) {
  struct sockaddr_in addr;
  int fd, childfd;
  int optval;

  std::thread([=] { UptimeServer(); }).detach();

  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("socket() failed %d\n", -errno);
    exit(1);
  }

  optval = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
	         (const void *)&optval, sizeof(int)) < 0) {
    printf("setsockopt() failed %d\n", -errno);
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

  if (listen(fd, SOMAXCONN) < 0) {
    printf("listen failed %d\n", -errno);
    exit(1);
  }

  while (true) {
    childfd = accept(fd, NULL, 0);
    if (childfd == -1) {
      printf("accept() failed %d\n", -errno);
      exit(1);
    }

    std::thread([=] { ServerWorker(childfd); }).detach();
  }
}

} // anonymous namespace

int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::cerr << "usage: [cmd] ..." << std::endl;
    return -EINVAL;
  }
  signal(SIGPIPE, SIG_IGN);

  std::string cmd = argv[1];
  if (cmd.compare("server") == 0) {
    ServerHandler(nullptr);
    return 0;
  } else {
    return 1;
  }
}
