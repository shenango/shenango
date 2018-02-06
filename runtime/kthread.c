/*
 * kthread.c - support for adding and removing kernel threads
 */

#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>

#include <base/cpu.h>
#include <base/list.h>
#include <base/lock.h>
#include <base/log.h>

#include "defs.h"

/* protects @ks and @nrks below */
DEFINE_SPINLOCK(klock);
/* the maximum number of kthreads */
unsigned int maxks;
/* the total number of kthreads (i.e. the size of @ks) */
unsigned int nrks;
/* an array of all the kthreads (for work-stealing) */
struct kthread *ks[NCPU];
/* kernel thread-local data */
__thread struct kthread *mykthread;

static struct kthread *allock(void)
{
	struct kthread *k;

	k = aligned_alloc(CACHE_LINE_SIZE,
			  align_up(sizeof(*k), CACHE_LINE_SIZE));
	if (!k)
		return NULL;

	memset(k, 0, sizeof(*k));
	spin_lock_init(&k->lock);
	list_head_init(&k->rq_overflow);
	mbufq_init(&k->txpktq_overflow);
	mbufq_init(&k->txcmdq_overflow);
	spin_lock_init(&k->timer_lock);
	k->park_efd = eventfd(0, 0);
	BUG_ON(k->park_efd < 0);
	return k;
}

/**
 * kthread_init_thread - initializes state for the kthread
 *
 * Returns 0 if successful, or -ENOMEM if out of memory.
 */
int kthread_init_thread(void)
{
	mykthread = allock();
	if (!mykthread)
		return -ENOMEM;

	return 0;
}

/**
 * kthread_attach - attaches the thread-local kthread to the runtime if it isn't
 * already attached
 *
 * An attached kthread participates in scheduling, RCU, and I/O.
 */
void kthread_attach(void)
{
	assert_spin_lock_held(&mykthread->lock);
	assert(mykthread->state == KTHREAD_STATE_PARKED_DETACHED ||
		mykthread->state == KTHREAD_STATE_PARKED_ATTACHED);

	if (mykthread->state == KTHREAD_STATE_PARKED_ATTACHED) {
		/* already attached */
		goto done;
	}

	spin_lock(&klock);
	assert(nrks < maxks);
	ks[nrks++] = mykthread;
	mykthread->rcu_gen = rcu_gen;
	spin_unlock(&klock);

done:
	mykthread->state = KTHREAD_STATE_ACTIVE;

}

/**
 * kthread_detach - detaches a kthread from the runtime if it isn't already
 * detached
 *
 * @r: the remote kthread to detach
 *
 * A detached kthread can no longer be stolen from. It must not receive I/O,
 * have outstanding timers, or participate in RCU.
 */
void kthread_detach(struct kthread *r)
{
	struct kthread *k = myk();
	unsigned int rgen;
	int i;

	assert_spin_lock_held(&r->lock);
	if (r->state != KTHREAD_STATE_PARKED_ATTACHED) {
		/* cannot be detached because active or already detached */
		return;
	}

	spin_lock(&klock);
	assert(r != k);
	assert(nrks > 0);
	for (i = 0; i < nrks; i++)
		if (ks[i] == r)
			goto found;
	BUG();

found:
	ks[i] = ks[--nrks];
	rgen = load_acquire(&rcu_gen);
	spin_unlock(&klock);

	/* remove from the current RCU generation */
	rcu_detach(r, rgen);

	/* steal all overflow packets and completions */
	mbufq_merge_to_tail(&k->txpktq_overflow, &r->txpktq_overflow);
	mbufq_merge_to_tail(&k->txcmdq_overflow, &r->txcmdq_overflow);

	/* TODO: merge timer queues */

	/* verify the kthread is correctly detached */
	assert(r->rq_head == 0);
	assert(r->rq_tail == 0);
	assert(list_empty(&r->rq_overflow));
	assert(mbufq_empty(&r->txpktq_overflow));
	assert(mbufq_empty(&r->txcmdq_overflow));
	assert(r->timern == 0);

	/* set state */
	r->state = KTHREAD_STATE_PARKED_DETACHED;
}
