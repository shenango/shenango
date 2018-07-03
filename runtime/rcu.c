/*
 * rcu.c - support for read-copy-update
 *
 * FIXME: Freeing objects is expensive with this minimal implementation. This
 * should be fine as long as RCU updates are rare. The Linux Kernel uses several
 * more optimized strategies that we may want to consider in the future.
 */

#include <base/stddef.h>
#include <base/lock.h>
#include <base/thread.h>
#include <runtime/rcu.h>
#include <runtime/sync.h>
#include <runtime/thread.h>

#include "defs.h"

/* Protects most of the RCU state below. */
static DEFINE_SPINLOCK(rcu_lock);
/* The current RCU reclaim generation number (protected by @klock). */
unsigned int rcu_gen;
/* The head of the RCU free list. */
static struct rcu_head *rcu_head;
/* A pointer to the pending RCU worker thread. */
static thread_t *rcu_th;
/* If nonzero, number of cores that haven't yet finished a quiescent period. */
static unsigned int rcu_reclaim_in_progress;

#ifdef DEBUG
__thread int rcu_read_count;
#endif /* DEBUG */

static void rcu_worker(void *arg)
{
	struct rcu_head *next, *head = (struct rcu_head *)arg;
	while (head) {
		next = head->next;
		head->func(head);
		head = next;
	}
}

/* starts an RCU reclaim period */
static void rcu_start_reclaim(void)
{
	assert_spin_lock_held(&rcu_lock);
	assert(rcu_reclaim_in_progress == 0);

	rcu_th = thread_create(rcu_worker, rcu_head);
	WARN_ON_ONCE(rcu_th == NULL);
	if (unlikely(!rcu_th))
		return;

	rcu_head = NULL;
	spin_lock(&klock);
	if (nrks == 1) {
		/* hot-path if only one thread is active */
		spin_unlock(&klock);
		thread_ready(rcu_th);
		rcu_th = NULL;
		return;
	}
	rcu_reclaim_in_progress = nrks - 1;
	store_release(&rcu_gen, rcu_gen + 1);
	spin_unlock(&klock);
	myk()->rcu_gen = rcu_gen;
}

/* finishes an RCU reclaim period */
static void rcu_finish_reclaim(void)
{
	assert_spin_lock_held(&rcu_lock);

	thread_ready(rcu_th);
	rcu_th = NULL;
	if (rcu_head)
		rcu_start_reclaim();
}

/**
 * rcu_free - frees an RCU object after the quiescent period
 * @head: the RCU head structure embedded within the object
 * @func: the release method
 */
void rcu_free(struct rcu_head *head, rcu_callback_t func)
{
	head->func = func;

	spin_lock_np(&rcu_lock);
	head->next = rcu_head;
	rcu_head = head;
	if (rcu_reclaim_in_progress == 0)
		rcu_start_reclaim();
	spin_unlock_np(&rcu_lock);
}

/* internal cold-path handler for reschedules */
void __rcu_recurrent(struct kthread *k)
{
	k->rcu_gen = rcu_gen; /* prevents future invocations for this gen */

	spin_lock(&rcu_lock);
	assert(rcu_reclaim_in_progress > 0);
	if (--rcu_reclaim_in_progress == 0)
		rcu_finish_reclaim();
	spin_unlock(&rcu_lock);
}

/**
 * rcu_detach - teardown RCU for a detached kthread
 * @k: the kthread that was detached
 * @rgen: the RCU generation number at the time of detach
 */
void rcu_detach(struct kthread *k, unsigned int rgen)
{
	if (k->rcu_gen == rcu_gen)
		return;

	__rcu_recurrent(k);
}
