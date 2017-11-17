#pragma once

extern "C" {
#include <errno.h>
#include <base/assert.h>
#include <runtime/thread.h>
}

#include <functional>

namespace rt {
namespace thread_internal {
extern void ThreadTrampoline(void *arg);
} // namespace thread_internal

// Spawns a new thread by copying.
static inline void ThreadSpawn(const std::function<void()>& func) {
  void *buf;
  thread_t *th = thread_create_with_buf(thread_internal::ThreadTrampoline, &buf,
					sizeof(std::function<void()>));
  if (unlikely(!th)) BUG();
  new(buf) std::function<void()>(func);
  thread_ready(th);
}

// Spawns a new thread by moving.
static inline void ThreadSpawn(std::function<void()>&& func) {
  void *buf;
  thread_t *th = thread_create_with_buf(thread_internal::ThreadTrampoline, &buf,
					sizeof(std::function<void()>));
  if (unlikely(!th)) BUG();
  new(buf) std::function<void()>(std::move(func));
  thread_ready(th);
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
