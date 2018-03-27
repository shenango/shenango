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

/* per kthread signal handling stack, configured with sigalstack(). */
static __thread struct stack *signal_stack;

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

	assert(ctx->uc_stack.ss_sp == (void *)signal_stack);

	STAT(PREEMPTIONS)++;

	/* resume execution if preemption is disabled */
	if (!preempt_enabled()) {
		set_preempt_needed();
		return;
	}

	/* save preempted state and park the kthread */
	spin_lock(&k->lock);
	k->preempted = true;
	k->preempted_ctx = ctx;
	k->preempted_fpstate = ctx->uc_mcontext.fpregs;
	BUG_ON(!thread_self());
	k->preempted_th = thread_self();

	/* park the kthread */
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

#define REDZONE_SIZE	128

/**
 * preempt_redirect_tf - reconfigures a thread's trap frame to reenter after
 *                       it was preempted
 * @th: the preempted thread
 * @ctx: the thread's ucontext_t to restore
 * @fpstate: the thread's floating point state to restore
 */
void preempt_redirect_tf(thread_t *th, ucontext_t *ctx,
			 struct _libc_fpstate *fpstate)
{
	struct thread_tf *tf = &th->tf;
	struct _libc_fpstate *frame_fpstate;
	ucontext_t *frame_ctx;

	/*
	 * Reserve space for a signal return frame on the preempted thread's
	 * stack. Note that the compiler can store data below the current stack
	 * pointer in a 128-byte region called the redzone, so leave enough
	 * space to make sure we don't overwrite it.
	 */
	tf->rsp = align_down(tf->rsp - sizeof(*frame_fpstate) - REDZONE_SIZE,
			     __WORD_SIZE);
	frame_fpstate = (struct _libc_fpstate *)tf->rsp;
	tf->rsp = align_down(tf->rsp - sizeof(*ctx), __WORD_SIZE);
	frame_ctx = (ucontext_t *)tf->rsp;
	BUG_ON(tf->rsp < (uintptr_t)th->stack ||
	       tf->rsp >= (uintptr_t)th->stack + sizeof(th->stack->usable));
	memcpy(frame_fpstate, fpstate, sizeof(*fpstate));
	memcpy(frame_ctx, ctx, sizeof(*ctx));

	/* ucontext_t contains a pointer, fix to reflect the stack location */
	frame_ctx->uc_mcontext.fpregs = frame_fpstate;

	/* disable do_sigalstack() in __rt_sigreturn() */
	frame_ctx->uc_stack.ss_flags = 3; /* invalid flags on purpose */

	/* point the instruction pointer to the reentry handler */
	tf->rip = (uintptr_t)&__rt_sigreturn;
	th->state = THREAD_STATE_RUNNABLE;
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
