#pragma once

extern "C" {
#include <errno.h>
#include <runtime/thread.h>
}

#include <functional>

namespace rt {
namespace thread_internal {
extern void ThreadTrampoline(void *arg);
} // namespace thread_internal

// Spawns a new thread by copying.
static inline int ThreadSpawn(const std::function<void()>& func) {
  void *buf;
  thread_t *th = thread_create_with_buf(thread_internal::ThreadTrampoline, &buf,
					sizeof(std::function<void()>));
  if (!th) return -ENOMEM;
  new(buf) std::function<void()>(func);
  thread_ready(th);
  return 0;
}

// Spawns a new thread by moving.
static inline int ThreadSpawn(std::function<void()>&& func) {
  void *buf;
  thread_t *th = thread_create_with_buf(thread_internal::ThreadTrampoline, &buf,
					sizeof(std::function<void()>));
  if (!th) return -ENOMEM;
  new(buf) std::function<void()>(std::move(func));
  thread_ready(th);
  return 0;
}

// Called from a running thread to exit.
static inline void ThreadExit(void) {
  thread_exit();
}

// Called from a running thread to yield.
static inline void ThreadYield(void) {
  thread_yield();
}

} // namespace rt
