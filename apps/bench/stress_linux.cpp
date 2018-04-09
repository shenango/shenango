
#include "fake_worker.h"

#include <iostream>
#include <chrono>
#include <thread>

namespace {

int threads;
uint64_t n;
std::string worker_spec;

void MainHandler(void *arg) {
  uint64_t cnt[threads] = {};

  for (int i = 0; i < threads; ++i) {
    std::thread([i, &cnt](){
      auto *w = FakeWorkerFactory(worker_spec);
      if (w == nullptr) {
        std::cerr << "Failed to create worker." << std::endl;
        exit(1);
      }

      while (true) {
        w->Work(n);
        cnt[i]++;
      }
    }).detach();
  }

  std::thread([&](){
    uint64_t last_total = 0;
    while (1) {
      uint64_t total = 0;
      for (int i = 0; i < threads; i++) total += cnt[i];
      std::cerr << total - last_total << std::endl;
      last_total = total;
      std::chrono::seconds sec(10);
      std::this_thread::sleep_for(sec);
    }
  }).join();

  // never returns
}

} // anonymous namespace

int main(int argc, char *argv[]) {

  if (argc != 4) {
    std::cerr << "usage: [#threads] [#n] [worker_spec]"
              << std::endl;
    return -EINVAL;
  }

  threads = std::stoi(argv[1], nullptr, 0);
  n = std::stoul(argv[2], nullptr, 0);
  worker_spec = std::string(argv[3]);

  MainHandler(NULL);

  return 0;
}
