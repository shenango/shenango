#include <chrono>
#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>

namespace {

using us = std::chrono::duration<double, std::micro>;
constexpr int kMeasureRounds = 1000000;

void BenchSpawnJoin() {
  for (int i = 0; i < kMeasureRounds; ++i) {
    auto th = std::thread([](){;});
    th.join();
  }
}

void BenchUncontendedMutex() {
  std::mutex m;
  volatile unsigned long foo = 0;

  for (int i = 0; i < kMeasureRounds; ++i) {
    std::unique_lock<std::mutex> l(m);
    foo++;
  }
}

void BenchYield() {
  auto th = std::thread([](){
    for (int i = 0; i < kMeasureRounds / 2; ++i)
      std::this_thread::yield();
  });

  for (int i = 0; i < kMeasureRounds / 2; ++i)
    std::this_thread::yield();

  th.join();
}

void BenchCondvarPingPong() {
  std::mutex m;
  std::condition_variable cv;
  bool dir = false; // shared and protected by @m.

  auto th = std::thread([&](){
    std::unique_lock<std::mutex> l(m);
    for (int i = 0; i < kMeasureRounds / 2; ++i) {
      while (dir)
        cv.wait(l);
      dir = true;
      cv.notify_one();
    }
  });

  std::unique_lock<std::mutex> l(m);
  for (int i = 0; i < kMeasureRounds / 2; ++i) {
    while (!dir)
      cv.wait(l);
    dir = false;
    cv.notify_one();
  }

  th.join();
}

void PrintResult(std::string name, us time) {
  time /= kMeasureRounds;
  std::cout << "test '" << name << "' took "<< time.count() << " us."
            << std::endl;
}

void MainHandler(void *arg) {
  auto start = std::chrono::steady_clock::now();
  BenchSpawnJoin();
  auto finish = std::chrono::steady_clock::now();
  PrintResult("SpawnJoin",
	std::chrono::duration_cast<us>(finish - start));

  start = std::chrono::steady_clock::now();
  BenchUncontendedMutex();
  finish = std::chrono::steady_clock::now();
  PrintResult("UncontendedMutex",
    std::chrono::duration_cast<us>(finish - start));

  start = std::chrono::steady_clock::now();
  BenchYield();
  finish = std::chrono::steady_clock::now();
  PrintResult("Yield",
    std::chrono::duration_cast<us>(finish - start));

  start = std::chrono::steady_clock::now();
  BenchCondvarPingPong();
  finish = std::chrono::steady_clock::now();
  PrintResult("CondvarPingPong",
    std::chrono::duration_cast<us>(finish - start));
}

} // anonymous namespace

int main(int argc, char *argv[]) {
  MainHandler(NULL);
  return 0;
}
