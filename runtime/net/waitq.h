/*
 * waitq.h - a light weight condition variable that works with locks instead of
 * mutexes.
 */

#pragma once

#include <base/list.h>
#include <runtime/thread.h>
#include <runtime/sync.h>

typedef struct waitq {
	struct list_head	waiters;
} waitq_t;

/**
 * waitq_wait - waits for the next signal
 * @q: the wake queue
 * @l: a held spinlock protecting the wake queue and the condition
 */
static inline void waitq_wait(waitq_t *q, spinlock_t *l)
{
	assert_spin_lock_held(l);
	list_add_tail(&q->waiters, &thread_self()->link);
	thread_park_and_unlock_np(l);
	spin_lock_np(l);
}

/**
 * waitq_signal - wakes up to one waiter on the wake queue
 * @q: the wake queue
 * @l: a held spinlock protecting the wake queue and the condition
 */
static inline thread_t *waitq_signal(waitq_t *q, spinlock_t *l)
{
	assert_spin_lock_held(l);
	return list_pop(&q->waiters, thread_t, link);
}

/**
 * waitq_signal_finish - finishes waking up to one waiter
 * @th: the thread to wake (if non-NULL)
 *
 * Call this method after dropping the lock to reduce the size of the critical
 * section.
 */
static inline void waitq_signal_finish(thread_t *th)
{
	if (th)
		thread_ready(th);
}

/**
 * waitq_signal_locked - wakes up to one waiter on the wake queue
 * @q: the wake queue
 * @l: a held spinlock protecting the wake queue and the condition
 */
static inline void waitq_signal_locked(waitq_t *q, spinlock_t *l)
{
	thread_t *th = waitq_signal(q, l);
	waitq_signal_finish(th);
}

/**
 * waitq_release - wakes all pending waiters
 * @q: the wake queue
 *
 * WARNING: the condition must have been updated with the lock held to
 * prevent future waiters. However, this method can be called after the
 * lock is released.
 */
static inline void waitq_release(waitq_t *q)
{
	while (true) {
		thread_t *th = list_pop(&q->waiters, thread_t, link);
		if (!th)
			break;
		thread_ready(th);
	}
}

static inline void waitq_release_start(waitq_t *q, struct list_head *waiters)
{
	list_append_list(waiters, &q->waiters);
}

static inline void waitq_release_finish(struct list_head *waiters)
{
	while (true) {
		thread_t *th = list_pop(waiters, thread_t, link);
		if (!th)
			break;
		thread_ready(th);
	}
}


/**
 * waitq_empty - returns true if there are no waiters
 * @q: the wait queue to check
 */
static inline bool waitq_empty(waitq_t *q)
{
	return list_empty(&q->waiters);
}

/**
 * waitq_init - initializes a wake queue
 * @q: the wake queue to initialize
 */
static inline void waitq_init(waitq_t *q)
{
	list_head_init(&q->waiters);
}
