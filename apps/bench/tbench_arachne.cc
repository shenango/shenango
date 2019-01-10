#include <chrono>
#include <iostream>

#include "Arachne/Arachne.h"


namespace {

using us = std::chrono::duration<double, std::micro>;
constexpr int kMeasureRounds = 1000000;

void empty_thread() {;}

void BenchSpawnJoin() {
  for (int i = 0; i < kMeasureRounds; ++i) {
    auto th = Arachne::createThread(empty_thread);
    Arachne::join(th);
  }
}

void BenchUncontendedMutex() {
  Arachne::SpinLock mutex;
  volatile unsigned long foo = 0;

  for (int i = 0; i < kMeasureRounds; ++i) {
    mutex.lock();
    foo++;
    mutex.unlock();
  }
}

void yielder() {
  for (int i = 0; i < kMeasureRounds / 2; ++i)
    Arachne::yield();
}

void BenchYield() {
  auto th = Arachne::createThread(yielder);
  yielder();
  Arachne::join(th);
}

struct pong {
  Arachne::SpinLock mutex;
  Arachne::ConditionVariable cv;
  bool dir = false;
};

void ping_pong_1(struct pong *p)
{
  p->mutex.lock();
  for (int i = 0; i < kMeasureRounds / 2; ++i) {
    while (p->dir)
      p->cv.wait(p->mutex);
    p->dir = true;
    p->cv.notifyOne();
  }
  p->mutex.unlock();
}

void BenchCondvarPingPong() {
  struct pong p;

  auto th = Arachne::createThread(ping_pong_1, &p);

  p.mutex.lock();
  for (int i = 0; i < kMeasureRounds / 2; ++i) {
    while (!p.dir)
      p.cv.wait(p.mutex);
    p.dir = false;
    p.cv.notifyOne();
  }

  Arachne::join(th);
}

void PrintResult(std::string name, us time) {
  time /= kMeasureRounds;
  std::cout << "test '" << name << "' took "<< time.count() << " us."
            << std::endl;
}

int MainHandler() {
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

  Arachne::shutDown();
  return 0;
}

} // anonymous namespace

// Requires coreArbiter: ./coreArbiterServer
int
main(int argc, const char** argv) {
    // Initialize the library
    Arachne::minNumCores = 1;
    Arachne::maxNumCores = 1;
    Arachne::disableLoadEstimation = true;
    Arachne::init(&argc, argv);

    Arachne::createThreadOnCore(2, MainHandler);

    Arachne::waitForTermination();
    return 0;
}
