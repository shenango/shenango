/*
 * sync.h - support for synchronization
 */

#pragma once

#include <base/stddef.h>
#include <base/list.h>
#include <base/atomic.h>


/*
 * Mutex support
 */

struct mutex {
	atomic_t		state;
	spinlock_t		waiter_lock;
	struct list_head	waiters;
};

typedef struct mutex mutex_t;

/* slow-path mutex routines */
extern void __mutex_lock(mutex_t *m);
extern void __mutex_unlock(mutex_t *m);

extern void mutex_init(mutex_t *m);

/**
 * assert_mutex_held - asserts that a mutex is currently held
 * @m: the mutex that must be held
 */
static inline void assert_mutex_held(mutex_t *m)
{
	assert(atomic_read(&m->state) > 0);
}

/**
 * mutex_try_lock - attempts to acquire a mutex
 * @m: the mutex to acquire
 *
 * Returns true if the acquire was successful.
 */
static inline bool mutex_try_lock(mutex_t *m)
{
	return atomic_cmpxchg(&m->state, 0, 1);
}

/**
 * mutex_lock - acquires a mutex
 * @m: the mutex to acquire
 */
static inline void mutex_lock(mutex_t *m)
{
	if (atomic_fetch_and_add(&m->state, 1))
		__mutex_lock(m);
}

/**
 * mutex_unlock - releases a mutex
 * @m: the mutex to release
 */
static inline void mutex_unlock(mutex_t *m)
{
	assert_mutex_held(m);
	if (atomic_sub_and_fetch(&m->state, 1))
		__mutex_unlock(m);
}


/*
 * Condition variable support
 */

struct condvar {
	spinlock_t		waiter_lock;
	struct list_head	waiters;
};

typedef struct condvar condvar_t;

extern void condvar_wait(condvar_t *cv, mutex_t *m);
extern void condvar_signal(condvar_t *cv);
extern void condvar_broadcast(condvar_t *cv);
extern void condvar_init(condvar_t *cv);


/*
 * Wait group support
 */

struct waitgroup {
	spinlock_t		lock;
	int			cnt;
	thread_t		*waiter;
};

typedef struct waitgroup waitgroup_t;

extern void waitgroup_add(waitgroup_t *wg, int cnt);
extern void waitgroup_wait(waitgroup_t *wg);
extern void waitgroup_init(waitgroup_t *wg);

/**
 * waitgroup_done - notifies the wait group that one waiting event completed
 * @wg: the wait group to complete
 */
static inline void waitgroup_done(waitgroup_t *wg)
{
	waitgroup_add(wg, -1);
}
