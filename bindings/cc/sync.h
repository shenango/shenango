
#pragma once

extern "C" {
#include <base/stddef.h>
#include <base/lock.h>
#include <runtime/sync.h>
}

// Spin lock support.
class Spin {
 public:
  Spin() { spin_lock_init(&lock_); }
  ~Spin() { assert(!spin_lock_held(&lock_)); }

  void Lock() { spin_lock(&lock_); }
  void Unlock() { spin_unlock(&lock_); }
  bool TryLock() { return spin_try_lock(&lock_); }

 private:
  spinlock_t lock_;

  Spin(const Spin&) = delete;
  Spin& operator=(const Spin&) = delete;
};

// Pthread-like mutex support.
class Mutex {
  friend class CondVar;

 public:
  Mutex() { mutex_init(&mu_); }
  ~Mutex() { assert(!mutex_held(&mu_)); }

  void Lock() { mutex_lock(&mu_); }
  void Unlock() { mutex_unlock(&mu_); }
  bool TryLock() { return mutex_try_lock(&mu_); }

 private:
  mutex_t mu_;

  Mutex(const Mutex&) = delete;
  Mutex& operator=(const Mutex&) = delete;
};

// RAII lock support (works with both Spin and Mutex).
template<typename L> class ScopedLock {
 public:
  explicit ScopedLock(L *lock) : lock_(lock) {
    lock_->Lock();
  }
  ~ScopedLock() { lock_->Unlock(); }

 private:
  L *const lock_;

  ScopedLock(const ScopedLock&) = delete;
  ScopedLock& operator=(const ScopedLock&) = delete;
};

// Pthread-like condition variable support.
class CondVar {
 public:
  CondVar() { condvar_init(&cv_); };
  ~CondVar() {}

  void Wait(Mutex *mu) { condvar_wait(&cv_, &mu->mu_); }
  void Signal() { condvar_signal(&cv_); }
  void SignalAll() { condvar_broadcast(&cv_); }

 private:
  condvar_t cv_;

  CondVar(const CondVar&) = delete;
  CondVar& operator=(const CondVar&) = delete;
};

// Golang-like waitgroup support.
class WaitGroup {
 public:
  WaitGroup() { waitgroup_init(&wg_); };
  WaitGroup(int count) {
    waitgroup_init(&wg_);
    waitgroup_add(&wg_, count);
  }
  ~WaitGroup() { assert(wg_.cnt == 0); };

  void Add(int count) { waitgroup_add(&wg_, count); }
  void Done() { Add(-1); }
  void Wait() { waitgroup_wait(&wg_); }

 private:
  waitgroup_t wg_;

  WaitGroup(const WaitGroup&) = delete;
  WaitGroup& operator=(const WaitGroup&) = delete;
};
