/*
 * preempt.c - support for kthread preemption
 */

#include <signal.h>
#include <string.h>

#include "base/log.h"
#include "runtime/thread.h"
#include "runtime/preempt.h"

#include "defs.h"

/* the current preemption count */
volatile __thread unsigned int preempt_cnt = PREEMPT_NOT_PENDING;

/* set a flag to indicate a preemption request is pending */
static void set_preempt_needed(void)
{
	preempt_cnt &= ~PREEMPT_NOT_PENDING;
}

/* handles preemption signals from the iokernel */
static void handle_sigusr1(int s, siginfo_t *si, void *ctx)
{
	struct kthread *k = myk();

	STAT(PREEMPTIONS)++;

	/* resume execution if preemption is disabled */
	if (!preempt_enabled()) {
		set_preempt_needed();
		return;
	}

	/* save preempted state and park the kthread */
	spin_lock(&k->lock);
	k->preempted = true;
	memcpy(&k->preempted_uctx, ctx, sizeof(k->preempted_uctx));
	k->preempted_th = thread_self();
	kthread_park(false);

	/* check if no other kthread stole our preempted work */
	if (k->preempted) {
		k->preempted = false;
		spin_unlock(&k->lock);
		return;
	}

	/* otherwise our context is executing elsewhere, return to scheduler */
	spin_unlock(&k->lock);
	sched_make_uctx((ucontext_t *)ctx);
	preempt_disable();
}

/**
 * preempt - entry point for preemption
 */
void preempt(void)
{
	assert(preempt_needed());
	clear_preempt_needed();
	thread_yield();
}

/**
 * preempt_reenter - jump back into a thread context that was preempted
 * @c: the ucontext of the thread
 */
void preempt_reenter(ucontext_t *c)
{
	sigset_t set;
	int ret;

	/*
	 * Temporarily mask SIGUSR1 to prevent preemption while loading
	 * the ucontext. It will get unmasked by setcontext().
	 */
	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	if (unlikely(pthread_sigmask(SIG_BLOCK, &set, NULL) < 0))
		log_err_ratelimited("preempt: couldn't mask SIGUSR1");

	preempt_enable();
	ret = setcontext(c);

	BUG_ON(ret != 0);
	unreachable();
}

/**
 * preempt_init - global initializer for preemption support
 *
 * Returns 0 if successful. otherwise fail.
 */
int preempt_init(void)
{
	struct sigaction act;

	act.sa_sigaction = handle_sigusr1;
	act.sa_flags = SA_SIGINFO;

	if (sigemptyset(&act.sa_mask) != 0) {
		log_err("couldn't empty the signal handler mask");
		return -errno;
	}

	if (sigaddset(&act.sa_mask, SIGUSR1)) {
		log_err("couldn't set signal handler mask");
		return -errno;
	}

	if (sigaction(SIGUSR1, &act, NULL) == -1) {
		log_err("couldn't register signal handler");
		return -errno;
	}

	return 0;
}
