// fake_worker.h - support for carefully controlled fake work generation

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>

class FakeWorker {
 public:
  // Perform n iterations of fake work.
  virtual void Work(uint64_t n) = 0;
};

class SqrtWorker : public FakeWorker {
 public:
  SqrtWorker() {}
  ~SqrtWorker() {}

  // Performs n iterations of sqrt().
  void Work(uint64_t n); 
};

class StridedMemtouchWorker : public FakeWorker {
 public:
  ~StridedMemtouchWorker() {delete buf_;}

  // Creates a strided memory touching worker.
  static StridedMemtouchWorker *Create(std::size_t size, size_t stride);

  // Performs n strided memory touches.
  void Work(uint64_t n);

 private:
  StridedMemtouchWorker(char *buf, std::size_t size, size_t stride) :
	buf_(buf), size_(size), stride_(stride) { }

  volatile char *buf_;
  std::size_t size_;
  std::size_t stride_;
};

class MemStreamWorker : public FakeWorker {
 public:
  ~MemStreamWorker();

  // Creates a memory streaming worker.
  static MemStreamWorker *Create(std::size_t size);

  // Performs n memory reads.
  void Work(uint64_t n);

 private:
  MemStreamWorker(char *buf, std::size_t size) :
  buf_(buf), size_(size) { }

  volatile char *buf_;
  std::size_t size_;
};

class RandomMemtouchWorker : public FakeWorker {
 public:
  ~RandomMemtouchWorker() {delete buf_;}

  // Creates a random memory touching worker.
  static RandomMemtouchWorker *Create(std::size_t size, unsigned int seed);

  // Performs n random memory touches.
  void Work(uint64_t n);

 private:
  RandomMemtouchWorker(char *buf, std::vector<unsigned int> schedule) :
	buf_(buf), schedule_(std::move(schedule)) { }

  volatile char *buf_;
  std::vector<unsigned int> schedule_;
};

// Parses a string to generate one of the above fake workers.
FakeWorker *FakeWorkerFactory(std::string s);
