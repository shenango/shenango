#include <cmath>
#include <algorithm>
#include <numeric>
#include <tuple>
#include <limits>
#include <random>

#include "fake_worker.h"

void SqrtWorker::Work(uint64_t n) {
  constexpr double kNumber = 2350845.545;
  for (uint64_t i = 0; i < n; ++i) {
    volatile double v = sqrt(i * kNumber);
    std::ignore = v; // silences compiler warning
  }
}

StridedMemtouchWorker *
StridedMemtouchWorker::Create(std::size_t size, std::size_t stride) {
  char *buf = new char[size]();
  return new StridedMemtouchWorker(buf, size, stride);
}

void StridedMemtouchWorker::Work(uint64_t n) {
  for (uint64_t i = 0; i < n; ++i)
    buf_[(stride_ * i) % size_]++;
}

RandomMemtouchWorker *
RandomMemtouchWorker::Create(std::size_t size, unsigned int seed) {
  char *buf = new char[size]();
  std::vector<unsigned int> v(size);
  std::iota(std::begin(v), std::end(v), 0);
  std::mt19937 g(seed);
  std::shuffle(v.begin(), v.end(), g);
  return new RandomMemtouchWorker(buf, std::move(v));
}

void RandomMemtouchWorker::Work(uint64_t n) {
  for (uint64_t i = 0; i < n; ++i)
    buf_[schedule_[i % schedule_.size()]]++;
}

namespace {

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

FakeWorker *FakeWorkerFactory(std::string s) {
  std::vector<std::string> tokens = split(s, ':');

  if (tokens[0] == "sqrt") {
    if (tokens.size() != 1) return nullptr;
    return new SqrtWorker();
  } else if (tokens[0] == "stridedmem") {
    if (tokens.size() != 3) return nullptr;
    unsigned long size = std::stoul(tokens[1], nullptr, 0);
    unsigned long stride = std::stoul(tokens[2], nullptr, 0);
    return StridedMemtouchWorker::Create(size, stride);
  } else if (tokens[0] == "randmem") {
    if (tokens.size() != 3) return nullptr;
    unsigned long size = std::stoul(tokens[1], nullptr, 0);
    unsigned long seed = std::stoul(tokens[2], nullptr, 0);
    if (seed > std::numeric_limits<unsigned int>::max()) return nullptr;
    return RandomMemtouchWorker::Create(size, seed);
  }

  // invalid type of worker
  return nullptr;
}
