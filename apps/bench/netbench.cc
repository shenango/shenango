extern "C" {
#include <base/log.h>
#include <net/ip.h>
}
#undef min
#undef max

#include "thread.h"
#include "sync.h"
#include "timer.h"
#include "udp.h"

#include <iostream>
#include <iomanip>
#include <utility>
#include <memory>
#include <chrono>
#include <vector>
#include <future>
#include <algorithm>
#include <numeric>

namespace {

using sec = std::chrono::duration<double, std::micro>;

// The netbench server responds to this port.
constexpr uint64_t kNetbenchPort = 8001;

// the number of worker threads to spawn.
int threads;
// the remote UDP address of the server.
udpaddr raddr;
// the time in seconds of each measurement.
int measure_sec;

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

void ServerWorker(rt::UdpConn *c, rt::WaitGroup *wg) {
  unsigned char buf[rt::UdpConn::kMaxPayloadSize];

  while (true) {
    // Receive a network response.
    ssize_t ret = c->Read(&buf, sizeof(buf));
    if (ret <= 0 || ret > static_cast<ssize_t>(sizeof(buf))) {
      if (ret == 0) break;
      panic("udp read failed, ret = %ld", ret);
    }

    // Send a network request.
    ssize_t sret = c->Write(&buf, ret);
    if (sret != ret) {
      if (ret == -ESHUTDOWN) break;
      panic("udp write failed, ret = %ld", ret);
    }
  }
}

void ServerHandler(void *arg) {
  std::unique_ptr<rt::UdpConn> c(rt::UdpConn::Listen({0, kNetbenchPort}));
  if (unlikely(c == nullptr)) panic("couldn't listen for control connections");

  while (true) {
    nbench_req req;
    udpaddr raddr;
    ssize_t ret = c->ReadFrom(&req, sizeof(req), &raddr);
    if (ret != sizeof(req) || req.magic != kMagic) continue;

    rt::Spawn([=, &c]{
      log_info("got connection %x:%d, %d seconds, %d ports", raddr.ip,
               raddr.port, req.measure_sec, req.nports);

      union {
        nbench_resp resp;
        char buf[rt::UdpConn::kMaxPayloadSize];
      };
      resp.magic = kMagic;
      resp.nports = req.nports;

      // Create the worker threads.
      rt::WaitGroup wg(req.nports);
      std::vector<std::unique_ptr<rt::UdpConn>> conns;
      for (int i = 0; i < req.nports; ++i) {
        std::unique_ptr<rt::UdpConn> cin(rt::UdpConn::Dial({0, 0}, raddr));
	if (unlikely(c == nullptr)) panic("couldn't dial data connection");
	resp.ports[i] = cin->LocalAddr().port;
        rt::Spawn(std::bind(ServerWorker, cin.get(), &wg));
        conns.emplace_back(std::move(cin));
      }

      // Send the port numbers to the client.
      ssize_t len = sizeof(nbench_resp) + sizeof(uint16_t) * req.nports;
      if (len > static_cast<ssize_t>(rt::UdpConn::kMaxPayloadSize))
        panic("too big");
      ssize_t ret = c->WriteTo(&resp, len, &raddr);
      if (ret != len) {
        log_err("udp write failed, ret = %ld", ret);
      }

      // Sleep for one extra second to give the experiment time to finish.
      rt::Sleep((req.measure_sec + 1) * rt::kSeconds);

      // Shutdown the workers and wait for them to exit.
      for (int i = 0; i < req.nports; i++)
        conns[i]->Shutdown();
      wg.Wait();
    });
  }
}

std::vector<double> ClientWorker(rt::UdpConn *c) {
  unsigned char buf[32] = {};
  std::vector<double> timings;

  while (true) {
    barrier();
    auto start = std::chrono::steady_clock::now();
    barrier();

    // Send a network request.
    ssize_t ret = c->Write(buf, sizeof(buf));
    if (ret != static_cast<ssize_t>(sizeof(buf))) {
      if (ret == -ESHUTDOWN) break;
      panic("udp write failed, ret = %ld", ret);
    }

    // Receive a network response.
    ret = c->Read(buf, sizeof(buf));
    if (ret != static_cast<ssize_t>(sizeof(buf))) {
      if (ret == 0) break;
      panic("udp read failed, ret = %ld", ret);
    }

    barrier();
    auto finish = std::chrono::steady_clock::now();
    barrier();

    timings.push_back(std::chrono::duration_cast<sec>(finish - start).count());
  }

  return timings;
}

void RunExperiment() {
    std::unique_ptr<rt::UdpConn> c(rt::UdpConn::Dial({0, 0}, raddr));
    if (c == nullptr) panic("couldn't establish control connection");

    // Send the control message.
    nbench_req req = {kMagic, threads, measure_sec};
    ssize_t ret = c->Write(&req, sizeof(req));
    if (ret != sizeof(req)) panic("couldn't send control message");

    // Receive the control response.
    union {
      nbench_resp resp;
      char buf[rt::UdpConn::kMaxPayloadSize];
    };
    ret = c->Read(&resp, rt::UdpConn::kMaxPayloadSize);
    if (ret < static_cast<ssize_t>(sizeof(nbench_resp)))
      panic("failed to receive control response");
    if (resp.magic != kMagic || resp.nports != threads)
      panic("got back invalid control response");

    // Create one UDP connection per thread.
    std::vector<std::unique_ptr<rt::UdpConn>> conns;
    for (int i = 0; i < threads; ++i) {
      std::unique_ptr<rt::UdpConn>
        outc(rt::UdpConn::Dial(c->LocalAddr(), {raddr.ip, resp.ports[i]}));
      if (unlikely(outc == nullptr)) panic("couldn't connect to raddr.");
      conns.emplace_back(std::move(outc));
    }

    // |--- start experiment duration timing ---|
    barrier();
    auto start = std::chrono::steady_clock::now();
    barrier();

    // Launch a worker thread for each connection.
    std::vector<std::future<std::vector<double>>> futures;
    for (int i = 0; i < threads; ++i) {
      auto pt = std::make_shared<std::packaged_task<std::vector<double>()>>
                  (std::bind(ClientWorker, conns[i].get()));
      futures.emplace_back(pt->get_future());
      rt::Spawn([=]{(*pt)();});
    }

    // Sleep for the experiment measurement duration.
    rt::Sleep(measure_sec * rt::kSeconds);

    // Shutdown all the connections.
    for (auto& c: conns)
      c->Shutdown();

    // Wait for the workers to finish.
    for (auto& f: futures)
      f.wait();

    // |--- end experiment duration timing ---|
    barrier();
    auto finish = std::chrono::steady_clock::now();
    barrier();

    // Aggregate all the latency timings together.
    std::vector<double> timings;
    for (auto& f: futures) {
      auto v = f.get();
      timings.insert(timings.end(), v.begin(), v.end());
    }

    // Report statistics.
    double elapsed = std::chrono::duration_cast<sec>(finish - start).count();
    double reqs_per_sec = static_cast<double>(timings.size()) /
                          elapsed * 1000000;
    std::sort(timings.begin(), timings.end());
    double sum = std::accumulate(timings.begin(), timings.end(), 0.0);
    double mean = sum / timings.size();
    double count = static_cast<double>(timings.size());
    double p9 = timings[count * 0.9];
    double p99 = timings[count * 0.99];
    double p999 = timings[count * 0.999];
    double p9999 = timings[count * 0.9999];
    double min = timings[0];
    double max = timings[timings.size() - 1];
    std::cout << std::setprecision(2) << std::fixed
              << "t: "       << threads
              << " rps: "    << reqs_per_sec
              << " n: "      << timings.size()
              << " min: "    << min
              << " mean: "   << mean
              << " 90%: "    << p9
              << " 99%: "    << p99
              << " 99.9%: "  << p999
              << " 99.99%: " << p9999
              << " max: "    << max << std::endl;
}

void ClientHandler(void *arg) {
  for (int i = 5; i <= 200; i+=5) {
    threads = i;
    RunExperiment();
    rt::Sleep(1 * rt::kSeconds);
  }
}

int StringToAddr(const char *str, uint32_t *addr) {
  uint8_t a, b, c, d;

  if(sscanf(str, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) != 4)
    return -EINVAL;

  *addr = MAKE_IP_ADDR(a, b, c, d);
  return 0;
}

} // anonymous namespace

int main(int argc, char *argv[]) {
  int ret;

  if (argc < 3) {
    std::cerr << "usage: [cfg_file] [cmd] ..." << std::endl;
    return -EINVAL;
  }

  std::string cmd = argv[2];
  if (cmd.compare("server") == 0) {
    ret = runtime_init(argv[1], ServerHandler, NULL);
    if (ret) {
      printf("failed to start runtime\n");
      return ret;
    }
  } else if (cmd.compare("client") != 0) {
    std::cerr << "invalid command: " << cmd << std::endl;
    return -EINVAL;
  }

  if (argc != 6) {
    std::cerr << "usage: [cfg_file] client [#threads] [remote_ip] [measure_sec]"
              << std::endl;
    return -EINVAL;
  }

  threads = std::stoi(argv[3], nullptr, 0);

  ret = StringToAddr(argv[4], &raddr.ip);
  if (ret) return -EINVAL;
  raddr.port = kNetbenchPort;

  measure_sec = std::stoi(argv[5], nullptr, 0);

  ret = runtime_init(argv[1], ClientHandler, NULL);
  if (ret) {
    printf("failed to start runtime\n");
    return ret;
  }

  return 0;
}
