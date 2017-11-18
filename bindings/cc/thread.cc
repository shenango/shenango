#include "thread.h"

namespace rt {
namespace thread_internal {
// A helper to jump from a C function to a C++ std::function.
void ThreadTrampoline(void *arg) {
  (*static_cast<std::function<void()>*>(arg))();
}

void ThreadTrampolineWithJoin(void *arg) {
  thread_internal::join_data *d = static_cast<thread_internal::join_data*>(arg);
  d->func_();
  spin_lock(&d->lock_);
  d->done_ = true;
  if (d->waiter_) {
    spin_unlock(&d->lock_);
    thread_ready(d->waiter_);
    return;
  }
  d->waiter_ = thread_self();
  thread_park_and_unlock(&d->lock_);
}
} // namespace thread_internal

Thread::~Thread() {
  if (unlikely(join_data_ != nullptr)) BUG();
}

Thread::Thread(const std::function<void()>& func) {
  thread_internal::join_data *buf;
  thread_t *th = thread_create_with_buf(
    thread_internal::ThreadTrampolineWithJoin,
    reinterpret_cast<void**>(&buf), sizeof(*buf));
  if (unlikely(!th)) BUG();
  new(buf) thread_internal::join_data(func);
  join_data_ = buf;
  thread_ready(th);
}

Thread::Thread(std::function<void()>&& func) {
  thread_internal::join_data *buf;
  thread_t *th = thread_create_with_buf(
    thread_internal::ThreadTrampolineWithJoin,
    reinterpret_cast<void**>(&buf), sizeof(*buf));
  if (unlikely(!th)) BUG();
  new(buf) thread_internal::join_data(std::move(func));
  join_data_ = buf;
  thread_ready(th);
}

void Thread::Detach() {
  join_data_ = nullptr;
}

void Thread::Join() {
  if (unlikely(join_data_ == nullptr)) BUG();

  spin_lock(&join_data_->lock_);
  if (join_data_->done_) {
    spin_unlock(&join_data_->lock_);
    thread_ready(join_data_->waiter_);
    join_data_ = nullptr;
    return;
  }
  join_data_->waiter_ = thread_self();
  thread_park_and_unlock(&join_data_->lock_);
  join_data_ = nullptr;
}

} // namespace rt
