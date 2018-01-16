/*
 * sync.c - support for synchronization
 */

#include <base/lock.h>
#include <base/log.h>
#include <runtime/thread.h>
#include <runtime/sync.h>

#include "defs.h"


/*
 * Mutex support
 */

/* handles contended mutex locking */
void __mutex_lock(mutex_t *m)
{
	thread_t *myth = thread_self();

	spin_lock(&m->waiter_lock);
	/* was the mutex released before we acquired the waiter lock? */
	if (!atomic_read(&m->state)) {
		if (!atomic_fetch_and_add(&m->state, 1)) {
			spin_unlock(&m->waiter_lock);
			return;
		}
	}
	list_add_tail(&m->waiters, &myth->link);
	thread_park_and_unlock(&m->waiter_lock);
}

/* handles contended mutex unlocking */
void __mutex_unlock(mutex_t *m)
{
	thread_t *waketh;

	spin_lock(&m->waiter_lock);
	waketh = list_pop(&m->waiters, thread_t, link);
	if (!waketh) {
		atomic_write(&m->state, 0);
		spin_unlock(&m->waiter_lock);
		return;
	}
	spin_unlock(&m->waiter_lock);
	thread_ready(waketh);
}

/**
 * mutex_init - initializes a mutex
 * @m: the mutex to initialize
 */
void mutex_init(mutex_t *m)
{
	atomic_write(&m->state, 0);
	spin_lock_init(&m->waiter_lock);
	list_head_init(&m->waiters);
}


/*
 * Condition variable support
 */

/**
 * condvar_wait - waits for a condition variable to be signalled
 * @cv: the condition variable to wait for
 * @m: the currently held mutex that projects the condition
 */
void condvar_wait(condvar_t *cv, mutex_t *m)
{
	thread_t *myth = thread_self();

	assert_mutex_held(m);
	spin_lock(&cv->waiter_lock);
	mutex_unlock(m);
	list_add_tail(&cv->waiters, &myth->link);
	thread_park_and_unlock(&cv->waiter_lock);

	mutex_lock(m);
}

/**
 * condvar_signal - signals a thread waiting on a condition variable
 * @cv: the condition variable to signal
 */
void condvar_signal(condvar_t *cv)
{
	thread_t *waketh;

	spin_lock(&cv->waiter_lock);
	waketh = list_pop(&cv->waiters, thread_t, link);
	spin_unlock(&cv->waiter_lock);
	if (waketh)
		thread_ready(waketh);
}

/**
 * condvar_broadcast - signals all waiting threads on a condition variable
 * @cv: the condition variable to signal
 */
void condvar_broadcast(condvar_t *cv)
{
	thread_t *waketh;

	spin_lock(&cv->waiter_lock);
	while (!list_empty(&cv->waiters)) {
		waketh = list_pop(&cv->waiters, thread_t, link);
		thread_ready(waketh);
	}
	spin_unlock(&cv->waiter_lock);
}

/**
 * condvar_init - initializes a condition variable
 * @cv: the condition variable to initialize
 */
void condvar_init(condvar_t *cv)
{
	spin_lock_init(&cv->waiter_lock);
	list_head_init(&cv->waiters);
}


/*
 * Wait group support
 */

/**
 * waitgroup_add - adds or removes waiters from a wait group
 * @wg: the wait group to update
 * @cnt: the count to add to the waitgroup (can be negative)
 *
 * If the wait groups internal count reaches zero, the waiting thread (if it
 * exists) will be signalled. The wait group must be incremented at least once
 * before calling waitgroup_wait().
 */
void waitgroup_add(waitgroup_t *wg, int cnt)
{
	spin_lock(&wg->lock);
	wg->cnt += cnt;
	BUG_ON(wg->cnt < 0);
	if (wg->cnt == 0 && wg->waiter != NULL)
		thread_ready(wg->waiter);
	spin_unlock(&wg->lock);
}

/**
 * waitgroup_wait - waits for the wait group count to become zero
 * @wg: the wait group to wait on
 */
void waitgroup_wait(waitgroup_t *wg)
{
	thread_t *myth = thread_self();

	spin_lock(&wg->lock);
	if (wg->cnt == 0) {
		spin_unlock(&wg->lock);
		return;
	}
	wg->waiter = myth;
	thread_park_and_unlock(&wg->lock);
}

/**
 * waitgroup_init - initializes a wait group
 * @wg: the wait group to initialize
 */
void waitgroup_init(waitgroup_t *wg)
{
	spin_lock_init(&wg->lock);
	wg->cnt = 0;
	wg->waiter = NULL;
}
