/*
 * kthread.c - support for adding and removing kernel threads
 */

#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <base/cpu.h>
#include <base/list.h>
#include <base/lock.h>
#include <base/log.h>
#include <runtime/timer.h>

#include "defs.h"

/* protects @ks and @nrks below */
DEFINE_SPINLOCK(klock);
/* the maximum number of kthreads */
unsigned int maxks;
/* the total number of attached kthreads (i.e. the size of @ks) */
unsigned int nrks = 0;
/* the number of active kthreads (not parked) */
unsigned int nactiveks = 0;
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
	k->detached = true;
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
static void kthread_attach(void)
{
	struct kthread *k = myk();

	assert(k->parked == false);
	assert(k->detached == true);

	k->detached = false;

	spin_lock(&klock);
	k->rcu_gen = rcu_gen;
	assert(nrks < maxks);
	ks[nrks] = k;
	store_release(&nrks, nrks + 1);
	nactiveks++;
	spin_unlock(&klock);
}

/**
 * kthread_detach_locked - detaches a kthread from the runtime
 * @r: the remote kthread to detach
 *
 * @r->lock must be held before calling this function.
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
	assert(r != k);
	assert(r->parked == true);
	assert(r->detached == false);

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

	/* merge timer queue into our own */
	timer_merge(r);

	/* verify the kthread is correctly detached */
	assert(r->rq_head == 0);
	assert(r->rq_tail == 0);
	assert(list_empty(&r->rq_overflow));
	assert(mbufq_empty(&r->txpktq_overflow));
	assert(mbufq_empty(&r->txcmdq_overflow));
	assert(r->timern == 0);

	/* set state */
	r->detached = true;
}

/*
 * kthread_park - block this kthread until the iokernel wakes it up.
 *
 * This variant must be called with the local kthread lock held. It is intended
 * for use by the scheduler and for use by signal handlers.
 */
void kthread_park(void)
{
	struct kthread *k = myk();
	uint64_t next_timer = 0, now = 0;
	unsigned long payload = 0;
	ssize_t s;
	uint64_t val;

	assert_spin_lock_held(&k->lock);
	assert(k->parked == false);

	spin_lock(&klock);
	if (nactiveks == 1 && nrks > 1) {
		/* must wait for other kthreads to detach so that timer heaps are
		 * merged */
		spin_unlock(&klock);
		return;
	}
	nactiveks--;
	spin_unlock(&klock);

	k->parked = true;
	/* get soonest timer expiry to convey to iokernel when parking */
	if (k->timern > 0) {
		next_timer = timer_earliest_deadline(k);
		now = microtime();

		if (next_timer <= now) {
			/* next timer has already expired */
			payload = TIMER_PENDING;
		} else
			payload = (next_timer - now) | TIMER_PENDING;
	}

	STAT(PARKS)++;
	spin_unlock(&k->lock);

	/* signal to iokernel that we're about to park */
	while (!lrpc_send(&k->txcmdq, TXCMD_NET_PARKING, payload))
		cpu_relax();

	/* yield to the iokernel */
	s = read(k->park_efd, &val, sizeof(val));
	BUG_ON(s != sizeof(uint64_t));
	BUG_ON(val != 1);

	/* iokernel has unparked us */

	/* reattach kthread if necessary */
	spin_lock(&k->lock);
	k->parked = false;
	if (k->detached)
		kthread_attach();
	else {
		spin_lock(&klock);
		nactiveks++;
		spin_unlock(&klock);
	}
}

/**
 * kthread_wait_to_attach - block this kthread until the iokernel wakes it up.
 *
 * This variant is intended for initialization.
 */
void kthread_wait_to_attach(void)
{
	struct kthread *k = myk();
	ssize_t s;
	uint64_t val;

	/* yield to the iokernel */
	s = read(k->park_efd, &val, sizeof(val));
	BUG_ON(s != sizeof(uint64_t));
	BUG_ON(val != 1);

	/* attach the kthread for the first time */
	kthread_attach();
}
