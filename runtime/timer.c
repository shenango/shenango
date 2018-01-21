/*
 * timer.c - support for timers
 *
 * So far we use a D-ary heap just like the Go runtime. We may want to consider
 * adding a lower-resolution shared timer wheel as well.
 */

#include <limits.h>
#include <stdlib.h>

#include <base/time.h>
#include <runtime/thread.h>
#include <runtime/timer.h>

#include "defs.h"

/* the arity of the heap */
#define D	4

struct timer_idx {
	uint64_t		deadline_us;
	struct timer_entry	*e;
};

static void sift_up(struct timer_idx *heap, int i)
{
	struct timer_idx tmp = heap[i];
	int p;

	while (i > 0) {
		p = (i - 1) / D;
		if (tmp.deadline_us >= heap[p].deadline_us)
			break;
		heap[i] = heap[p];
		heap[i].e->idx = i;
		heap[p] = tmp;
		heap[p].e->idx = p;
		i = p;
	}
}

static void sift_down(struct timer_idx *heap, int i, int n)
{
	struct timer_idx tmp = heap[i];
	uint64_t w;
	int c, j;

	while (1) {
		w = tmp.deadline_us;
		c = INT_MAX;
		for (j = (i * D + 1); j <= (i * D + D); j++) {
			if (j + i >= n)
				break;
			if (heap[j].deadline_us < w) {
				w = heap[j].deadline_us;
				c = j;
			}
		}
		if (c == INT_MAX)
			break;
		heap[i] = heap[c];
		heap[i].e->idx = i;
		heap[c] = tmp;
		heap[c].e->idx = c;
		i = c;
	}
}

static void timer_start_locked(struct timer_entry *e, uint64_t deadline_us)
{
	struct kthread *k = myk();
	int i;

	assert_spin_lock_held(&k->timer_lock);

	/* can't insert a timer twice! */
	BUG_ON(e->armed);

	i = k->timern++;
	if (k->timern >= RUNTIME_MAX_TIMERS) {
		/* TODO: support unlimited timers */
		BUG();
	}

	k->timers[i].deadline_us = deadline_us;
	k->timers[i].e = e;
	e->idx = i;
	sift_up(k->timers, i);
	e->armed = true;
}


/**
 * timer_start - arms a timer
 * @e: the timer entry to start
 * @deadline_us: the deadline in microseconds
 *
 * @e must have been initialized with timer_init().
 */
void timer_start(struct timer_entry *e, uint64_t deadline_us)
{
	struct kthread *k = myk();

	spin_lock(&k->timer_lock);
	timer_start_locked(e, deadline_us);
	spin_unlock(&k->timer_lock);
}

/**
 * timer_cancel - cancels a timer
 * @e: the timer entry to cancel
 *
 * Returns true if the timer was successfully cancelled, otherwise it has
 * already fired or was never armed.
 */
bool timer_cancel(struct timer_entry *e)
{
	struct kthread *k = myk();
	int last;

	spin_lock(&k->timer_lock);
	if (!e->armed) {
		spin_unlock(&k->timer_lock);
		return false;
	}
	e->armed = false;

	last = --k->timern;
	if (e->idx == last) {
		spin_unlock(&k->timer_lock);
		return true;
	}

	k->timers[e->idx] = k->timers[last];
	k->timers[e->idx].e->idx = e->idx;
	sift_up(k->timers, e->idx);
	sift_down(k->timers, e->idx, k->timern);
	spin_unlock(&k->timer_lock);

	return true;
}

static void timer_finish_sleep(unsigned long arg)
{
	thread_t *th = (thread_t *)arg;
	thread_ready(th);
}

static void __timer_sleep(uint64_t deadline_us)
{
	struct kthread *k = myk();
	struct timer_entry e;

	timer_init(&e, timer_finish_sleep, (unsigned long)thread_self());
	spin_lock(&k->timer_lock);
	timer_start_locked(&e, deadline_us);
	thread_park_and_unlock(&k->timer_lock);
}

/**
 * timer_sleep_until - sleeps until a deadline
 * @deadline_us: the deadline time in microseconds
 */
void timer_sleep_until(uint64_t deadline_us)
{
	if (unlikely(microtime() >= deadline_us))
		return;

	__timer_sleep(deadline_us);
}

/**
 * timer_sleep - sleeps for a duration
 * @duration_us: the duration time in microseconds
 */
void timer_sleep(uint64_t duration_us)
{
	__timer_sleep(microtime() + duration_us);
}

static void timer_worker(void *arg)
{
	struct kthread *k = arg;
	struct timer_entry *e;
	uint64_t now_us;
	int i;

	spin_lock(&k->timer_lock);

	now_us = microtime();
	while (k->timern > 0 && k->timers[0].deadline_us <= now_us) {
		i = --k->timern;
		e = k->timers[0].e;
		if (i > 0) {
			k->timers[0] = k->timers[i];
			k->timers[0].e->idx = 0;
			sift_down(k->timers, 0, i);
		}
		spin_unlock(&k->timer_lock);

		/* execute the timer handler */
		e->fn(e->arg);

		spin_lock(&k->timer_lock);
		now_us = microtime();
	}

	spin_unlock(&k->timer_lock);
}

/**
 * timer_run - creates a closure for timer processing
 * @k: the kthread from which to process timeouts
 *
 * Returns a thread that handles timer processing when executed or
 * NULL if no timers have expired.
 */
thread_t *timer_run(struct kthread *k)
{
	thread_t *th;
	uint64_t now_us = microtime();

	/* deliberate race condition */
	if (k->timern == 0 || k->timers[0].deadline_us > now_us)
		return NULL;

	th = thread_create(timer_worker, k);
	if (unlikely(!th))
		return NULL;

	th->state = THREAD_STATE_RUNNABLE;
	return th;
}

/**
 * timer_init_thread - initializes per-thread timer state
 *
 * Returns 0 if successful, otherwise fail.
 */
int timer_init_thread(void)
{
	struct kthread *k = myk();

	k->timers = malloc(sizeof(struct timer_idx) * RUNTIME_MAX_TIMERS);
	if (!k->timers)
		return -ENOMEM;

	return 0;
}
