extern "C" {
#include <base/log.h>
#include <net/ip.h>
}
#undef min
#undef max

#include "thread.h"
#include "sync.h"
#include "timer.h"
#include "net.h"
#include "fake_worker.h"

#include <iostream>
#include <iomanip>
#include <utility>
#include <memory>
#include <chrono>
#include <vector>
#include <algorithm>
#include <numeric>
#include <random>
#include <utility>

namespace {

constexpr uint64_t kNetbenchPort = 8001;

struct payload {
  uint64_t work_iterations;
  uint64_t index;
};

using namespace std::chrono;
using sec = duration<double, std::micro>;

// The maximum lateness to tolerate before dropping egress samples.
constexpr uint64_t kMaxCatchUpUS = 5;

// the number of worker threads to spawn.
int threads;
// the remote UDP address of the server.
netaddr raddr;
// the mean service time in us.
double st;
// number of iterations required for 1us on target server
int iterations_per_us = 83;

// Number of seconds to warmup at rate 0
constexpr uint64_t kWarmupUpSeconds = 5;

static std::vector<std::pair<double, uint64_t>> rates;

void ServerWorker(std::unique_ptr<rt::TcpConn> c) {
  payload p;
  std::unique_ptr<FakeWorker> w(FakeWorkerFactory("stridedmem:3200:64"));
  if (w == nullptr) panic("couldn't create worker");

  while (true) {
    // Receive a network response.
    ssize_t ret = c->ReadFull(&p, sizeof(p));
    if (ret <= 0 || ret > static_cast<ssize_t>(sizeof(p))) {
      if (ret == 0 || ret == -ECONNRESET) break;
      panic("read failed, ret = %ld", ret);
    }

    // Perform fake work if requested.
    uint64_t workn = ntoh64(p.work_iterations);
    if (workn != 0) w->Work(workn); //82.0

    // Send a network request.
    ssize_t sret = c->WriteFull(&p, ret);
    if (sret != ret) {
      if (sret == -EPIPE || sret == -ECONNRESET) break;
      panic("write failed, ret = %ld", sret);
    }
  }
}

void ServerHandler(void *arg) {
  std::unique_ptr<rt::TcpQueue> q(rt::TcpQueue::Listen({0, kNetbenchPort},
				  4096));
  if (q == nullptr) panic("couldn't listen for connections");

  while (true) {
    rt::TcpConn *c = q->Accept();
    if (c == nullptr) panic("couldn't accept a connection");
    rt::Thread([=]{ServerWorker(std::unique_ptr<rt::TcpConn>(c));}).Detach();
  }
}

struct work_unit {
  double start_us, work_us, duration_us;
};

template <class Arrival, class Service>
std::vector<work_unit> GenerateWork(Arrival a, Service s, double cur_us, double last_us) {
  std::vector<work_unit> w;
  while (cur_us < last_us) {
    cur_us += a();
    w.emplace_back(work_unit{cur_us, s(), 0});
  }
  return w;
}

std::vector<work_unit>
ClientWorker(rt::TcpConn *c, rt::WaitGroup *starter,
             std::function<std::vector<work_unit>()> wf) {
  constexpr int kBatchSize = 32;
  std::vector<work_unit> w(wf());
  std::vector<std::chrono::time_point<std::chrono::steady_clock>> timings;
  timings.reserve(w.size());

  // Start the receiver thread.
  auto th = rt::Thread([&]{
    payload rp;

    while (true) {
     ssize_t ret = c->ReadFull(&rp, sizeof(rp));
     if (ret != static_cast<ssize_t>(sizeof(rp))) {
       if (ret == 0 || ret < 0) break;
       panic("read failed, ret = %ld", ret);
     }

     barrier();
     auto ts = steady_clock::now();
     barrier();
     uint64_t idx = ntoh64(rp.index);
     w[idx].duration_us = duration_cast<sec>(ts - timings[idx]).count();
    }
  });

  // Synchronized start of load generation.
  starter->Done();
  starter->Wait();

  barrier();
  auto expstart = std::chrono::steady_clock::now();
  barrier();

  payload p[kBatchSize];
  int j = 0;
  auto wsize = w.size();

  for (unsigned int i = 0; i < wsize; ++i) {
    barrier();
    auto now = steady_clock::now();
    barrier();
    if (duration_cast<sec>(now - expstart).count() < w[i].start_us) {
      ssize_t ret = c->WriteFull(p, sizeof(payload) * j);
      if (ret != static_cast<ssize_t>(sizeof(payload) * j))
        panic("write failed, ret = %ld", ret);
      j = 0;
      now = steady_clock::now();
      rt::Sleep(w[i].start_us - duration_cast<sec>(now - expstart).count());
    }
    if (duration_cast<sec>(now - expstart).count() - w[i].start_us >
        kMaxCatchUpUS)
      continue;

    barrier();
    timings[i] = steady_clock::now();
    barrier();

    // Enqueue a network request.
    p[j].work_iterations = hton64(static_cast<uint64_t>(w[i].work_us * iterations_per_us));
    p[j].index = hton64(i);
    j++;

    if (j >= kBatchSize || i == wsize - 1) {
      ssize_t ret = c->WriteFull(p, sizeof(payload) * j);
      if (ret != static_cast<ssize_t>(sizeof(payload) * j))
        panic("write failed, ret = %ld", ret);
      j = 0;
    }
  }

  rt::Sleep(5000 * rt::kMilliseconds);

  c->Shutdown(SHUT_RDWR);
  th.Join();

  return w;
}

std::vector<work_unit>
RunExperiment(int threads, double *reqs_per_sec,
              std::function<std::vector<work_unit>()> wf) {
  // Create one TCP connection per thread.
  std::vector<std::unique_ptr<rt::TcpConn>> conns;
  for (int i = 0; i < threads; ++i) {
    std::unique_ptr<rt::TcpConn> outc(rt::TcpConn::Dial({0, 0}, raddr));
    if (unlikely(outc == nullptr)) panic("couldn't connect to raddr.");
    conns.emplace_back(std::move(outc));
  }

  // Launch a worker thread for each connection.
  rt::WaitGroup starter(threads + 1);
  std::vector<rt::Thread> th;
  std::unique_ptr<std::vector<work_unit>> samples[threads];
  for (int i = 0; i < threads; ++i) {
    th.emplace_back(rt::Thread([&, i]{
      auto v = ClientWorker(conns[i].get(), &starter, wf);
      samples[i].reset(new std::vector<work_unit>(std::move(v)));
    }));
  }

  // Give the workers time to initialize, then start recording.
  starter.Done();
  starter.Wait();

  // |--- start experiment duration timing ---|
  barrier();
  auto start = std::chrono::steady_clock::now();
  barrier();

  // Wait for the workers to finish.
  for (auto& t: th)
    t.Join();

  // |--- end experiment duration timing ---|
  barrier();
  auto finish = std::chrono::steady_clock::now();
  barrier();

  // Close the connections.
  for (auto& c: conns)
    c->Abort();

  // Aggregate all the samples together.
  uint64_t total = 0;
  std::vector<work_unit> w;
  for (int i = 0; i < threads; ++i) {
    auto &v = *samples[i];
    total += v.size();
    w.insert(w.end(), v.begin(), v.end());
  }

  // Report results.
  double elapsed = std::chrono::duration_cast<sec>(finish - start).count();
  if (reqs_per_sec != nullptr)
    *reqs_per_sec = static_cast<double>(total) / elapsed * 1000000;
  return w;
}

void SteadyStateExperiment(int threads, double req_rate, double service_time) {
  constexpr int kRounds = 1;
  std::vector<work_unit> w;
  double reqs_per_sec = 0;

  for (int i = 0; i < kRounds; i++) {
    double tmp;
    auto t = RunExperiment(threads, &tmp, [=]{
      std::mt19937 g(rand());
      std::exponential_distribution<double>
        rd(1.0 / (1000000.0 / (req_rate / static_cast<double>(threads))));
      std::exponential_distribution<double> wd(1.0 / service_time);
      return GenerateWork(std::bind(rd, g), std::bind(wd, g), 0, 1000000); 
    });
    w.insert(w.end(), t.begin(), t.end());
    reqs_per_sec += tmp;
    rt::Sleep(500 * rt::kMilliseconds);
  }

  w.erase(std::remove_if(w.begin(), w.end(),
                         [](const work_unit& s){return s.duration_us == 0;}),
          w.end());
  reqs_per_sec /= kRounds;
  std::sort(w.begin(), w.end(),
            [](const work_unit& s1, work_unit& s2){
              return s1.duration_us < s2.duration_us;});
  double sum = std::accumulate(w.begin(), w.end(), 0.0,
    [](double s, const work_unit& c){return s + c.duration_us;});
  double mean = sum / w.size();
  double count = static_cast<double>(w.size());
  double p9 = w[count * 0.9].duration_us;
  double p99 = w[count * 0.99].duration_us;
  double p999 = w[count * 0.999].duration_us;
  double p9999 = w[count * 0.9999].duration_us;
  double min = w[0].duration_us;
  double max = w[w.size() - 1].duration_us;
  std::cout << std::setprecision(2) << std::fixed
            << "t: "       << threads
            << " rps: "    << reqs_per_sec
            << " n: "      << w.size()
            << " min: "    << min
            << " mean: "   << mean
            << " 90%: "    << p9
            << " 99%: "    << p99
            << " 99.9%: "  << p999
            << " 99.99%: " << p9999
            << " max: "    << max << std::endl;
}

void LoadShiftExperiment(int threads, const std::vector<std::pair<double, uint64_t>> &rates,
                         double service_time) {
  auto w = RunExperiment(threads, nullptr, [=]{
    std::mt19937 g(rand());
    std::exponential_distribution<double> wd(1.0 / service_time);
    std::vector<work_unit> w1;
    uint64_t last_us = 0;
    for (auto &r : rates) {
      std::exponential_distribution<double>
        rd(1.0 / (1000000.0 / (r.first / static_cast<double>(threads))));
      auto work = GenerateWork(std::bind(rd, g), std::bind(wd, g), last_us, last_us + r.second);
      last_us = work.back().start_us;
      w1.insert(w1.end(), work.begin(), work.end()); 
    }
    return w1;
  });

  w.erase(std::remove_if(w.begin(), w.end(),
                         [](const work_unit& s){return s.duration_us == 0 || s.start_us < kWarmupUpSeconds * 1e6;}),
          w.end());
  std::sort(w.begin(), w.end(), [](const work_unit& s1, work_unit& s2){
    return s1.start_us < s2.start_us;
  });

  for (const work_unit& i : w) {
    std::cout << std::setprecision(2) << std::fixed
              << i.start_us << ":" << i.duration_us << std::endl;
  }
}

void ClientHandler(void *arg) {
  LoadShiftExperiment(threads, rates, st);
#if 0
  for (double i = 100000; i <= 8000000; i += 100000)
    SteadyStateExperiment(threads, i, st);
#endif
}

int StringToAddr(const char *str, uint32_t *addr) {
  uint8_t a, b, c, d;

  if(sscanf(str, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) != 4)
    return -EINVAL;

  *addr = MAKE_IP_ADDR(a, b, c, d);
  return 0;
}

std::vector<std::string> split(const std::string &text, char sep) {
  std::vector<std::string> tokens;
  std::string::size_type start = 0, end = 0;
  while ((end = text.find(sep, start)) != std::string::npos) {
    tokens.push_back(text.substr(start, end - start));
    start = end + 1;
  }
  tokens.push_back(text.substr(start));
  return tokens;
}

} // anonymous namespace

int main(int argc, char *argv[]) {
  int i, ret;

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

  if (argc < 7) {
    std::cerr << "usage: [cfg_file] client [#threads] [remote_ip] [service_us] [<request_rate>:<us_duration>]..." << std::endl;
    return -EINVAL;
  }

  threads = std::stoi(argv[3], nullptr, 0);

  ret = StringToAddr(argv[4], &raddr.ip);
  if (ret) return -EINVAL;
  raddr.port = kNetbenchPort;

  st = std::stod(argv[5], nullptr);

  for (i = 6; i < argc; i++) {
    std::vector<std::string> tokens = split(argv[i], ':');
    if (tokens.size() != 2)
      return -EINVAL;
    double rate = std::stod(tokens[0], nullptr);
    uint64_t duration = std::stoll(tokens[1], nullptr, 0);
    if (i == 6) {
      rates.emplace_back(rate, kWarmupUpSeconds * 1e6); 
    }
    rates.emplace_back(rate, duration);
  }

  ret = runtime_init(argv[1], ClientHandler, NULL);
  if (ret) {
    printf("failed to start runtime\n");
    return ret;
  }

  return 0;
}
