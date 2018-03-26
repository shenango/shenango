/*
 * sched.c - a scheduler for user-level threads
 */

#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include <base/stddef.h>
#include <base/lock.h>
#include <base/list.h>
#include <base/hash.h>
#include <base/limits.h>
#include <base/tcache.h>
#include <base/slab.h>
#include <base/log.h>
#include <runtime/sync.h>
#include <runtime/thread.h>

#include "defs.h"

/* the currently running thread, or NULL if in runtime code */
__thread thread_t *__self;
/* a pointer to the top of the per-kthread (TLS) runtime stack */
static __thread void *runtime_stack;
/* a pointer to the bottom of the per-kthread (TLS) runtime stack */
static __thread void *runtime_stack_base;
/* a pointer to the per-kthread signal stack */
__thread struct stack *signal_stack;

/* fast allocation of struct thread */
static struct slab thread_slab;
static struct tcache *thread_tcache;
static DEFINE_PERTHREAD(struct tcache_perthread, thread_pt);

/* used to track cycle usage in scheduler */
static __thread uint64_t last_tsc;

/**
 * In inc/runtime/thread.h, this function is declared inline (rather than static
 * inline) so that it is accessible to the Rust bindings. As a result, it must
 * also appear in a source file to avoid linker errors.
 */
thread_t *thread_self(void);

/**
 * jmp_thread - runs a thread, popping its trap frame
 * @th: the thread to run
 *
 * This function restores the state of the thread and switches from the runtime
 * stack to the thread's stack. Runtime state is not saved.
 */
static __noreturn void jmp_thread(thread_t *th)
{
	__self = th;
	assert(th->state == THREAD_STATE_RUNNABLE);
	th->state = THREAD_STATE_RUNNING;
	__jmp_thread(&th->tf);
}

/**
 * jmp_runtime - saves the current trap frame and jumps to a function in the
 *               runtime
 * @fn: the runtime function to call
 * @arg: an argument to pass to the runtime function
 *
 * WARNING: Only threads can call this function.
 *
 * This function saves state of the running thread and switches to the runtime
 * stack, making it safe to run the thread elsewhere.
 */
static void jmp_runtime(runtime_fn_t fn, unsigned long arg)
{
	preempt_disable();
	assert(thread_self() != NULL);
	__jmp_runtime(&thread_self()->tf, fn, runtime_stack, arg);
}

/**
 * jmp_runtime_nosave - jumps to a function in the runtime without saving the
 *			caller's state
 * @fn: the runtime function to call
 * @arg: an argument to pass to the runtime function
 */
static __noreturn void jmp_runtime_nosave(runtime_fn_t fn, unsigned long arg)
{
	preempt_disable();
	__jmp_runtime_nosave(fn, runtime_stack, arg);
}

static bool rxq_spin_us(struct kthread *k, uint64_t us)
{
	uint64_t cycles = us * cycles_per_us;
	unsigned long start = rdtsc();

	while (rdtsc() - start < cycles) {
		if (!lrpc_empty(&k->rxq))
			return true;
		cpu_relax();
	}

	return false;
}

static void drain_overflow(struct kthread *l)
{
	thread_t *th;

	assert_spin_lock_held(&l->lock);

	while (l->rq_head - l->rq_tail < RUNTIME_RQ_SIZE) {
		th = list_pop(&l->rq_overflow, thread_t, link);
		if (!th)
			break;
		l->rq[l->rq_head++ % RUNTIME_RQ_SIZE] = th;
	}
}

static bool steal_work(struct kthread *l, struct kthread *r)
{
	size_t fpstate_offset;
	ucontext_t uctx;
	thread_t *th;
	uint32_t i, avail, rq_tail;

	assert_spin_lock_held(&l->lock);
	assert(l->rq_head == 0 && l->rq_tail == 0);

	if (!spin_try_lock(&r->lock))
		return false;

	/* harmless race condition */
	if (unlikely(r->detached)) {
		spin_unlock(&r->lock);
		return false;
	}

	/* resume execution of a preempted thread */
	if (r->preempted) {
		__self = r->preempted_th;
		r->preempted = false;
		memcpy(&uctx, &r->preempted_uctx, sizeof(uctx));
		fpstate_offset = r->fpstate_offset;
		spin_unlock(&r->lock);
		spin_unlock(&l->lock);
		preempt_reenter(&uctx, fpstate_offset);

		/* preempt_reenter() doesn't return */
		unreachable();
	}

	/* try to steal directly from the runqueue */
	avail = load_acquire(&r->rq_head) - r->rq_tail;
	if (avail) {
		/* steal half the tasks */
		avail = div_up(avail, 2);
		assert(avail <= div_up(RUNTIME_RQ_SIZE, 2));
		rq_tail = r->rq_tail;
		for (i = 0; i < avail; i++)
			l->rq[i] = r->rq[rq_tail++ % RUNTIME_RQ_SIZE];
		l->rq_head = avail;
		store_release(&r->rq_tail, rq_tail);
		spin_unlock(&r->lock);

		STAT(THREADS_STOLEN) += avail;
		return true;
	}

	/* check for overflow tasks */
	th = list_pop(&r->rq_overflow, thread_t, link);
	if (th)
		goto done;

	/* check for timeouts */
	th = timer_run(r);
	if (th) {
		STAT(TIMERS_STOLEN)++;
		goto done;
	}

	/* check the network queues */
	th = net_run(r, RUNTIME_NET_BUDGET);
	if (th) {
		STAT(NETS_STOLEN)++;
		goto done;
	}

done:
	/* either enqueue the stolen work or detach the kthread */
	if (th) {
		l->rq[l->rq_head++] = th;
		STAT(THREADS_STOLEN)++;
	} else if (r->parked) {
		kthread_detach(r);

		if (l->rq_head != l->rq_tail) {
			/* handle the case where kthread_detach -> rcu_detach leads to a
			 * thread being added to the runqueue (but not returned above) */
			th = l->rq[l->rq_head];
		}
	}

	spin_unlock(&r->lock);
	return th != NULL;
}

/* the main scheduler routine, decides what to run next */
static __noreturn void schedule(void)
{
	struct kthread *r = NULL, *l = myk();
	uint64_t start_tsc, end_tsc;
	thread_t *th;
	unsigned int last_nrks;
	int i, sibling;

	/* detect misuse of preempt disable */
	BUG_ON((preempt_cnt & ~PREEMPT_NOT_PENDING) != 1);

	/* update entry stat counters */
	STAT(RESCHEDULES)++;
	start_tsc = rdtsc();
	STAT(PROGRAM_CYCLES) += start_tsc - last_tsc;

	/* mark the end of the RCU quiescent period */
	rcu_recurrent();
	/* drain overflow packets */
	net_recurrent();

	__self = NULL;
	spin_lock(&l->lock);

	assert(l->parked == false);
	assert(l->detached == false);

	/* park if we have been preempted */
	if (unlikely(preempt_needed())) {
		clear_preempt_needed();
		kthread_park(false);
	}

	/* move overflow tasks into the runqueue */
	if (unlikely(!list_empty(&l->rq_overflow)))
		drain_overflow(l);

again:
	/* first try the local runqueue */
	if (l->rq_head != l->rq_tail)
		goto done;

	/* reset the local runqueue since it's empty */
	l->rq_head = l->rq_tail = 0;

	/* then check for local timeouts */
	th = timer_run(l);
	if (th) {
		STAT(TIMERS_LOCAL)++;
		l->rq[l->rq_head++] = th;
		goto done;
	}

	/* then try the local network queues */
	th = net_run(l, RUNTIME_NET_BUDGET);
	if (th) {
		STAT(NETS_LOCAL)++;
		l->rq[l->rq_head++] = th;
		goto done;
	}

	last_nrks = load_acquire(&nrks);

	/* then try to steal from a sibling kthread */
	sibling = cpu_map[l->curr_cpu].sibling_core;
	r = cpu_map[sibling].recent_kthread;
	if (r && r != l && steal_work(l, r))
		goto done;

	/* then try to steal from a random kthread */
	r = ks[rand_crc32c((uintptr_t)l) % last_nrks];
	if (r != l && steal_work(l, r))
		goto done;

	/* finally try to steal from every kthread */
	for (i = 0; i < last_nrks; i++) {
		if (ks[i] == l)
			continue;
		if (steal_work(l, ks[i]))
			goto done;
	}

	/*
	 * Last try, spin poll on the RXQ for a little while.
	 * If we don't, completions may arrive just after parking.
	 */
	if (rxq_spin_us(l, RUNTIME_PARK_POLL_US)) {
		th = net_run(l, RUNTIME_NET_BUDGET);
		if (th) {
			STAT(NETS_LOCAL)++;
			l->rq[l->rq_head++] = th;
			goto done;
		}
	}

	/* did not find anything to run, park this kthread */
	STAT(SCHED_CYCLES) += rdtsc() - start_tsc;
	kthread_park(true);
	start_tsc = rdtsc();

	goto again;

done:
	/* pop off a thread and run it */
	assert(l->rq_head != l->rq_tail);
	th = l->rq[l->rq_tail++ % RUNTIME_RQ_SIZE];

	/* check if we have emptied the runqueue */
	if (l->rq_head == l->rq_tail)
		gen_inactive(&l->rq_gen);

	spin_unlock(&l->lock);

	/* update exit stat counters */
	end_tsc = rdtsc();
	STAT(SCHED_CYCLES) += end_tsc - start_tsc;
	last_tsc = end_tsc;

	jmp_thread(th);
}

/**
 * immediately park each kthread when it first starts up, only schedule it once
 * the iokernel has granted it a core
 */
static __noreturn void schedule_start(void)
{
	/* force kthread parking (iokernel assumes all kthreads are parked
	 * initially) */
	kthread_wait_to_attach();

	schedule();
}

static void thread_finish_park_and_unlock(unsigned long data)
{
	thread_t *myth = thread_self();
	spinlock_t *lock = (spinlock_t *)data;

	assert(myth->state == THREAD_STATE_RUNNING);
	myth->state = THREAD_STATE_SLEEPING;
	spin_unlock(lock);

	schedule();
}

static void thread_finish_park_and_unlock_np(unsigned long data)
{
	thread_t *myth = thread_self();
	spinlock_t *lock = (spinlock_t *)data;

	assert(myth->state == THREAD_STATE_RUNNING);
	myth->state = THREAD_STATE_SLEEPING;
	spin_unlock_np(lock);

	schedule();
}

/**
 * thread_park_and_unlock - puts a thread to sleep and unlocks when finished
 * @l: this lock will be released when the thread state is fully saved
 */
void thread_park_and_unlock(spinlock_t *l)
{
	/* this will switch from the thread stack to the runtime stack */
	jmp_runtime(thread_finish_park_and_unlock, (unsigned long)l);
}

/**
 * thread_park_and_unlock_np - puts a thread to sleep and unlocks when finished
 * and re-enables preemption
 * @l: this lock will be released when the thread state is fully saved
 */
void thread_park_and_unlock_np(spinlock_t *l)
{
	/* this will switch from the thread stack to the runtime stack */
	jmp_runtime(thread_finish_park_and_unlock_np, (unsigned long)l);
}


/**
 * thread_ready - marks a thread as a runnable
 * @th: the thread to mark runnable
 *
 * This function can only be called when @th is sleeping.
 */
void thread_ready(thread_t *th)
{
	struct kthread *k;
	uint32_t rq_tail;

	assert(th->state == THREAD_STATE_SLEEPING);
	th->state = THREAD_STATE_RUNNABLE;

	k = getk();
	rq_tail = load_acquire(&k->rq_tail);
	if (unlikely(k->rq_head - rq_tail >= RUNTIME_RQ_SIZE)) {
		assert(k->rq_head - rq_tail == RUNTIME_RQ_SIZE);
		spin_lock(&k->lock);
		list_add_tail(&k->rq_overflow, &th->link);
		spin_unlock(&k->lock);
		putk();
		return;
	}

	/* at least one thread to run - we are in a generation */
	gen_active(&k->rq_gen);

	k->rq[k->rq_head % RUNTIME_RQ_SIZE] = th;
	store_release(&k->rq_head, k->rq_head + 1);
	putk();
}

static void thread_finish_yield(unsigned long data)
{
	thread_t *myth = thread_self();

	assert(myth->state == THREAD_STATE_RUNNING);
	myth->state = THREAD_STATE_SLEEPING;
	thread_ready(myth);

	schedule();
}

/**
 * thread_yield - yields the currently running thread
 *
 * Yielding will give other threads a chance to run.
 */
void thread_yield(void)
{
	/* this will switch from the thread stack to the runtime stack */
	jmp_runtime(thread_finish_yield, 0);
}

static __always_inline thread_t *__thread_create(void)
{
	struct thread *th;
	struct stack *s;

	preempt_disable();
	th = tcache_alloc(&perthread_get(thread_pt));
	if (unlikely(!th)) {
		preempt_enable();
		return NULL;
	}

	s = stack_alloc();
	if (unlikely(!s)) {
		tcache_free(&perthread_get(thread_pt), th);
		preempt_enable();
		return NULL;
	}
	preempt_enable();

	th->stack = s;
	th->state = THREAD_STATE_SLEEPING;
	th->main_thread = false;

	return th;
}

/**
 * thread_create - creates a new thread
 * @fn: a function pointer to the starting method of the thread
 * @arg: an argument passed to @fn
 *
 * Returns 0 if successful, otherwise -ENOMEM if out of memory.
 */
thread_t *thread_create(thread_fn_t fn, void *arg)
{
	thread_t *th = __thread_create();
	if (unlikely(!th))
		return NULL;

	th->tf.rsp = stack_init_to_rsp(th->stack, thread_exit);
	th->tf.rdi = (uint64_t)arg;
	th->tf.rbp = (uint64_t)0; /* just in case base pointers are enabled */
	th->tf.rip = (uint64_t)fn;
	return th;
}

/**
 * thread_create_with_buf - creates a new thread with space for a buffer on the
 * stack
 * @fn: a function pointer to the starting method of the thread
 * @buf: a pointer to the stack allocated buffer (passed as arg too)
 * @buf_len: the size of the stack allocated buffer
 *
 * Returns 0 if successful, otherwise -ENOMEM if out of memory.
 */
thread_t *thread_create_with_buf(thread_fn_t fn, void **buf, size_t buf_len)
{
	void *ptr;
	thread_t *th = __thread_create();
	if (unlikely(!th))
		return NULL;

	th->tf.rsp = stack_init_to_rsp_with_buf(th->stack, &ptr,
						buf_len, thread_exit);
	th->tf.rdi = (uint64_t)ptr;
	th->tf.rbp = (uint64_t)0; /* just in case base pointers are enabled */
	th->tf.rip = (uint64_t)fn;
	*buf = ptr;
	return th;
}

/**
 * thread_spawn - creates and launches a new thread
 * @fn: a function pointer to the starting method of the thread
 * @arg: an argument passed to @fn
 *
 * Returns 0 if successful, otherwise -ENOMEM if out of memory.
 */
int thread_spawn(thread_fn_t fn, void *arg)
{
	thread_t *th = thread_create(fn, arg);
	if (unlikely(!th))
		return -ENOMEM;
	thread_ready(th);
	return 0;
}

/**
 * thread_spawn_main - creates and launches the main thread
 * @fn: a function pointer to the starting method of the thread
 * @arg: an argument passed to @fn
 *
 * WARNING: Only can be called once.
 *
 * Returns 0 if successful, otherwise -ENOMEM if out of memory.
 */
int thread_spawn_main(thread_fn_t fn, void *arg)
{
	static bool called = false;
	thread_t *th;

	BUG_ON(called);
	called = true;

	th = thread_create(fn, arg);
	if (!th)
		return -ENOMEM;
	th->main_thread = true;
	thread_ready(th);
	return 0;
}

static void thread_finish_exit(unsigned long data)
{
	struct thread *th = thread_self();

	/* if the main thread dies, kill the whole program */
	if (unlikely(th->main_thread))
		init_shutdown(EXIT_SUCCESS);
	stack_free(th->stack);
	tcache_free(&perthread_get(thread_pt), th);

	schedule();
}

/**
 * thread_exit - terminates a thread
 */
void thread_exit(void)
{
	/* can't free the stack we're currently using, so switch */
	jmp_runtime_nosave(thread_finish_exit, 0);
}

/**
 * sched_start - used only to enter the runtime the first time
 */
void sched_start(void)
{
	last_tsc = rdtsc();
	jmp_runtime_nosave((runtime_fn_t)schedule_start, 0);
}

/**
 * sched_make_uctx - initializes an existing ucontext so it jumps into the
 *		     scheduler to reschedule
 * @c: a valid, existing ucontext (from a signal handler or getcontext()).
 */
void sched_make_uctx(ucontext_t *c)
{
	c->uc_mcontext.gregs[REG_RIP] = (uintptr_t)schedule;
	c->uc_mcontext.gregs[REG_RSP] = (uintptr_t)runtime_stack;
	c->uc_link = 0;
}

static void runtime_top_of_stack(void)
{
	panic("a runtime function returned to the top of the stack");
}

/**
 * sched_init_thread - initializes per-thread state for the scheduler
 *
 * Returns 0 if successful, or -ENOMEM if out of memory.
 */
int sched_init_thread(void)
{
	struct stack *s;
	stack_t new_stack, old_stack;

	tcache_init_perthread(thread_tcache, &perthread_get(thread_pt));

	s = stack_alloc();
	if (!s)
		return -ENOMEM;

	runtime_stack_base = (void *)s;
	runtime_stack = (void *)stack_init_to_rsp(s, runtime_top_of_stack); 

	signal_stack = stack_alloc();
	if (!signal_stack)
		return -ENOMEM;

	new_stack.ss_sp = (void *)signal_stack;
	new_stack.ss_size = sizeof(signal_stack->usable);
	new_stack.ss_flags =  0;

	return sigaltstack(&new_stack, &old_stack);
}

/**
 * sched_init - initializes the scheduler subsystem
 *
 * Returns 0 if successful, or -ENOMEM if out of memory.
 */
int sched_init(void)
{
	int ret, i, j, siblings;

	/*
	 * set up allocation routines for threads
	 */
	ret = slab_create(&thread_slab, "runtime_threads",
			  sizeof(struct thread), 0);
	if (ret)
		return ret;

	thread_tcache = slab_create_tcache(&thread_slab,
					   TCACHE_DEFAULT_MAG_SIZE);
	if (!thread_tcache) {
		slab_destroy(&thread_slab);
		return -ENOMEM;
	}

	for (i = 0; i < cpu_count; i++) {
		siblings = 0;
		bitmap_for_each_set(cpu_info_tbl[i].thread_siblings_mask, cpu_count, j) {
			if (i == j)
				continue;
			BUG_ON(siblings++);
			cpu_map[i].sibling_core = j;
		}
	}

	return 0;
}
