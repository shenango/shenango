/*
 * kthread.c - support for adding and removing kernel threads
 */

#include <stdlib.h>
#include <string.h>

#include <base/cpu.h>
#include <base/list.h>
#include <base/lock.h>

#include "defs.h"

/* protects @ks and @nrks below */
DEFINE_SPINLOCK(klock);
/* the total number of kthreads (i.e. the size of @ks) */
unsigned int nrks;
/* an array of all the kthreads (for work-stealing) */
struct kthread *ks[NTHREAD];
/* kernel thread-local data */
__thread struct kthread *mykthread;

static struct kthread *allock(void)
{
	struct kthread *k;

	k = malloc(sizeof(*k));
	if (!k)
		return NULL;

	memset(k, 0, sizeof(*k));
	spin_lock_init(&k->lock);
	list_head_init(&k->rq_overflow);
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
 * kthread_attach - attaches the thread-local kthread to the runtime
 *
 * An attached kthread participates in scheduling, RCU, and I/O.
 */
void kthread_attach(void)
{
	spin_lock(&klock);
	assert(nrks < cpu_count - 1);
	ks[nrks++] = mykthread;
	rcu_tlgen = rcu_gen;
	spin_unlock(&klock);
}

/**
 * kthread_detach - detaches the thread-local kthread from the runtime
 *
 * A detached kthread no longer handles scheduling, RCU, and I/O.
 * TODO: Early prototype. Probably need more synchronization.
 */
void kthread_detach(void)
{
	int i;

	spin_lock(&klock);
	assert(nrks > 0);
	for (i = 0; i < nrks; i++)
		if (ks[i] == mykthread)
			goto found;
	BUG();

found:
	ks[i] = ks[nrks--];
	spin_unlock(&klock);
}
