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
static void handle_sigusr1(int s, siginfo_t *si, void *c)
{
	struct kthread *k = myk();

	STAT(PREEMPTIONS)++;
	set_preempt_needed();

	/* resume execution if preemption is disabled */
	if (!preempt_enabled())
		return;

	thread_yield_kthread();

	/* note: gcc does seem to recompute myk() */
	if (myk() != k)
		STAT(PREEMPTIONS_STOLEN)++;
}

/**
 * preempt - entry point for preemption
 */
void preempt(void)
{
	assert(preempt_needed());
	thread_yield_kthread();
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
	act.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER | SA_RESTART;

	if (sigemptyset(&act.sa_mask) != 0) {
		log_err("couldn't empty the signal handler mask");
		return -errno;
	}

	if (sigaction(SIGUSR1, &act, NULL) == -1) {
		log_err("couldn't register signal handler");
		return -errno;
	}

	return 0;
}
