/*
 * sync.h - support for synchronization
 */

#pragma once

#include <base/stddef.h>
#include <base/list.h>
#include <runtime/thread.h>


/*
 * Mutex support
 */

struct mutex {
	bool			held;
	spinlock_t		waiter_lock;
	struct list_head	waiters;
};

typedef struct mutex mutex_t;

extern bool mutex_try_lock(mutex_t *m);
extern void mutex_lock(mutex_t *m);
extern void mutex_unlock(mutex_t *m);
extern void mutex_init(mutex_t *m);

/**
 * mutex_held - is the mutex currently held?
 * @m: the mutex to check
 */
static inline bool mutex_held(mutex_t *m)
{
	return m->held;
}

/**
 * assert_mutex_held - asserts that a mutex is currently held
 * @m: the mutex that must be held
 */
static inline void assert_mutex_held(mutex_t *m)
{
	assert(mutex_held(m));
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
