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

static __thread struct stack *signal_stack;
static __thread struct stack *bounce_stack;


/* set a flag to indicate a preemption request is pending */
static void set_preempt_needed(void)
{
	preempt_cnt &= ~PREEMPT_NOT_PENDING;
}

/* handles preemption signals from the iokernel */
static void handle_sigusr1(int s, siginfo_t *si, void *c)
{
	struct kthread *k = myk();
	ucontext_t *ctx = c;

	assert(ctx->uc_stack.ss_sp == (void*)signal_stack);

	STAT(PREEMPTIONS)++;

	/* resume execution if preemption is disabled */
	if (!preempt_enabled()) {
		set_preempt_needed();
		return;
	}

	/* save preempted state and park the kthread */
	spin_lock(&k->lock);
	k->preempted = true;
	k->preempted_ctx = c;
	k->preempted_th = thread_self();
	k->stack_end = &signal_stack->guard;

	kthread_park(false);

	/* check if no other kthread stole our preempted work */
	if (k->preempted) {
		k->preempted = false;
		spin_unlock(&k->lock);
		return;
	}

	/* otherwise our context is executing elsewhere, return to scheduler */
	spin_unlock(&k->lock);
	sched_make_uctx(ctx);
	preempt_disable();
}

/**
 * preempt - entry point for preemption
 */
void preempt(void)
{
	assert(preempt_needed());
	thread_yield();
}

/**
 * preempt_reenter - jump back into a thread context that was preempted
 * @l: the local kthread stealing the trap frame
 * @r: the remote kthread being stolen from
 */
void preempt_reenter(struct kthread *l, struct kthread *r)
{
	sigset_t set;
	size_t frame_size, fpstate_offset;
	ucontext_t *ctx;

	frame_size = (uintptr_t)r->stack_end - (uintptr_t)r->preempted_ctx;
	ctx = (ucontext_t *)((uintptr_t)bounce_stack->guard - frame_size);
	memcpy(ctx, r->preempted_ctx, frame_size);
	fpstate_offset = (uintptr_t)r->preempted_ctx->uc_mcontext.fpregs - (uintptr_t)r->preempted_ctx;
	ctx->uc_mcontext.fpregs = (void *)((uintptr_t)ctx + fpstate_offset);

	r->preempted = false;
	spin_unlock(&r->lock);
	spin_unlock(&l->lock);


	/*
	 * Temporarily mask SIGUSR1 to prevent preemption while loading
	 * the ucontext. It will get unmasked by __jmp_restore_sigctx().
	 */
	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	if (unlikely(pthread_sigmask(SIG_BLOCK, &set, NULL) < 0))
		WARN();

	/* Re-arm with the correct local signal stack */
	ctx->uc_stack.ss_sp = (void*)signal_stack;
	ctx->uc_stack.ss_size =  sizeof(signal_stack->usable);
	ctx->uc_stack.ss_flags = 0;

	preempt_enable();
	__jmp_restore_sigctx(ctx);

	unreachable();
}

/**
 * preempt_init_thread - per-thread initializer for preemption support
 *
 * Returns 0 if successful. otherwise fail.
 */
int preempt_init_thread(void)
{
	stack_t new_stack, old_stack;

	signal_stack = stack_alloc();
	if (!signal_stack)
		return -ENOMEM;

	bounce_stack = stack_alloc();
	if (!bounce_stack) {
		stack_free(signal_stack);
		return -ENOMEM;
	}

	new_stack.ss_sp = (void *)signal_stack;
	new_stack.ss_size = sizeof(signal_stack->usable);
	new_stack.ss_flags =  0;

	return sigaltstack(&new_stack, &old_stack);
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
	act.sa_flags = SA_SIGINFO | SA_ONSTACK;

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
