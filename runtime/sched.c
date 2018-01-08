/*
 * sched.c - a scheduler for user-level threads
 */

#include <stdlib.h>

#include <base/stddef.h>
#include <base/lock.h>
#include <base/list.h>
#include <base/hash.h>
#include <base/limits.h>
#include <base/tcache.h>
#include <base/slab.h>
#include <base/log.h>
#include <runtime/thread.h>

#include "defs.h"

/* the currently running thread, or NULL if in runtime code */
__thread thread_t *__self;
/* a pointer to the top of the per-kernel-thread (TLS) runtime stack */
static __thread void *runtime_stack;

/* fast allocation of struct thread */
static struct slab thread_slab;
static struct tcache *thread_tcache;
static __thread struct tcache_perthread thread_pt;

/**
 * call_thread - runs a thread, popping its trap frame
 * @th: the thread to run
 *
 * This function restores the state of the thread and switches from the runtime
 * stack to the thread's stack. Runtime state is not saved.
 */
static __noreturn void call_thread(thread_t *th)
{
	__self = th;
	assert(th->state == THREAD_STATE_RUNNABLE);
	th->state = THREAD_STATE_RUNNING;
	__pop_tf(&th->tf);
}

/**
 * call_runtime - saves the current trap frame and calls a function in the
 *                runtime
 * @fn: the runtime function to call
 * @arg: an argument to pass to the runtime function
 *
 * WARNING: Only threads can call this function.
 *
 * This function saves state of the running thread and switches to the runtime
 * stack, making it safe to run the thread elsewhere.
 */
static void call_runtime(runtime_fn_t fn, unsigned long arg)
{
	assert(thread_self() != NULL);
	__call_runtime(&thread_self()->tf, fn, runtime_stack, arg);
}

/**
 * call_runtime_nosave - calls a function in the runtime without saving the
 *			 trap frame
 * @fn: the runtime function to call
 * @arg: an argument to pass to the runtime function
 */
static __noreturn void call_runtime_nosave(runtime_fn_t fn, unsigned long arg)
{
	struct thread_tf tf;
	tf.rbp = (uint64_t)0; /* just in case base pointers are enabled */
	tf.rip = (uint64_t)fn;
	tf.rsp = (uint64_t)runtime_stack;
	__pop_tf(&tf);
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
	thread_t *th;
	uint32_t i, avail, rq_tail;

	assert_spin_lock_held(&l->lock);
	assert(l->rq_head == 0 && l->rq_tail == 0);

	if (!spin_try_lock(&r->lock))
		return false;
	avail = load_acquire(&r->rq_head) - r->rq_tail;
	if (!avail) {
		/* check for overflow tasks */
		th = list_pop(&r->rq_overflow, thread_t, link);

		/* check for timeouts */
		if (!th)
			th = timer_run(r);

		/* check the network queues */
		if (!th)
			th = net_run(r, RUNTIME_NET_BUDGET);

		if (th)
			l->rq[l->rq_head++] = th;
		spin_unlock(&r->lock);
		return th != NULL;
	}

	/* steal half the tasks */
	avail = div_up(avail, 2);
	assert(avail <= div_up(RUNTIME_RQ_SIZE, 2));
	rq_tail = r->rq_tail;
	for (i = 0; i < avail; i++)
		l->rq[i] = r->rq[rq_tail++ % RUNTIME_RQ_SIZE];
	l->rq_head = avail;
	store_release(&r->rq_tail, rq_tail);
	spin_unlock(&r->lock);

	return true;
}

/* the main scheduler routine, decides what to run next */
static __noreturn void schedule(void)
{
	thread_t *th;
	struct kthread *r, *l = myk();
	int i;

	/* mark the end of the RCU quiescent period */
	rcu_recurrent();
	/* drain overflow packets */
	net_recurrent();

	__self = NULL;
	spin_lock(&l->lock);

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
		l->rq[l->rq_head++] = th;
		goto done;
	}

	/* then try the local network queues */
	th = net_run(l, RUNTIME_NET_BUDGET);
	if (th) {
		l->rq[l->rq_head++] = th;
		goto done;
	}

	/* then attempt to steal tasks or packets from a random kthread */
	r = ks[rand_crc32c((uintptr_t)l) % nrks];
	if (steal_work(l, r))
		goto done;

	/* finally try to steal from every kthread */
	for (i = 0; i < nrks; i++) {
		if (ks[i] == l)
			continue;
		if (steal_work(l, ks[i]))
			goto done;
	}

	/* did not find anything to run */
	cpu_relax();
	/* TODO: park the kthread here instead of trying again */
	goto again;

done:
	/* pop off a thread and run it */
	assert(l->rq_head != l->rq_tail);
	th = l->rq[l->rq_tail++ % RUNTIME_RQ_SIZE];
	spin_unlock(&l->lock);
	call_thread(th);
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

/**
 * thread_park_and_unlock - puts a thread to sleep and unlocks when finished
 * @lock: this lock will be released when the thread state is fully saved
 */
void thread_park_and_unlock(spinlock_t *lock)
{
	/* this will switch from the thread stack to the runtime stack */
	call_runtime(thread_finish_park_and_unlock, (unsigned long)lock);
}

/**
 * thread_ready_lock_held - marks a thread as a runnable
 * expects lock for myk() to be held already
 * @th: the thread to mark runnable
 *
 * This function can only be called when @th is sleeping.
 */
void thread_ready_lock_held(thread_t *th)
{
	struct kthread *k = myk();
	uint32_t rq_tail;

	assert(th->state == THREAD_STATE_SLEEPING);
	th->state = THREAD_STATE_RUNNABLE;

	rq_tail = load_acquire(&k->rq_tail);
	if (unlikely(k->rq_head - rq_tail >= RUNTIME_RQ_SIZE)) {
		assert(k->rq_head - rq_tail == RUNTIME_RQ_SIZE);
		assert_spin_lock_held(&k->lock);
		list_add_tail(&k->rq_overflow, &th->link);
		return;
	}

	k->rq[k->rq_head % RUNTIME_RQ_SIZE] = th;
	store_release(&k->rq_head, k->rq_head + 1);
}

/**
 * thread_ready - marks a thread as a runnable
 * @th: the thread to mark runnable
 *
 * This function can only be called when @th is sleeping.
 */
void thread_ready(thread_t *th)
{
	struct kthread *k = myk();
	uint32_t rq_tail;

	assert(th->state == THREAD_STATE_SLEEPING);
	th->state = THREAD_STATE_RUNNABLE;

	rq_tail = load_acquire(&k->rq_tail);
	if (unlikely(k->rq_head - rq_tail >= RUNTIME_RQ_SIZE)) {
		assert(k->rq_head - rq_tail == RUNTIME_RQ_SIZE);
		spin_lock(&k->lock);
		list_add_tail(&k->rq_overflow, &th->link);
		spin_unlock(&k->lock);
		return;
	}

	k->rq[k->rq_head % RUNTIME_RQ_SIZE] = th;
	store_release(&k->rq_head, k->rq_head + 1);
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
	call_runtime(thread_finish_yield, 0);
}

static __always_inline thread_t *__thread_create(void)
{
	struct thread *th;
	struct stack *s;

	th = tcache_alloc(&thread_pt);
	if (unlikely(!th))
		return NULL;

	s = stack_alloc();
	if (unlikely(!s)) {
		tcache_free(&thread_pt, th);
		return NULL;
	}

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
 * @arg: an argument passed to @fn
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
 * thread_spawn_lock_held - creates and launches a new thread
 * @fn: a function pointer to the starting method of the thread
 * @arg: an argument passed to @fn
 * myk()->lock must be held!
 *
 * Returns 0 if successful, otherwise -ENOMEM if out of memory.
 */
int thread_spawn_lock_held(thread_fn_t fn, void *arg)
{
	thread_t *th = thread_create(fn, arg);
	if (unlikely(!th))
		return -ENOMEM;
	thread_ready_lock_held(th);
	return 0;
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
	tcache_free(&thread_pt, th);

	schedule();
}

/**
 * thread_exit - terminates a thread
 */
void thread_exit(void)
{
	/* can't free the stack we're currently using, so switch */
	call_runtime_nosave(thread_finish_exit, 0);
}

/**
 * sched_start - used only to enter the runtime the first time
 */
void sched_start(void)
{
	call_runtime_nosave((runtime_fn_t)schedule, 0);
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

	tcache_init_perthread(thread_tcache, &thread_pt);

	s = stack_alloc();
	if (!s)
		return -ENOMEM;

	runtime_stack = (void *)stack_init_to_rsp(s, runtime_top_of_stack); 
	return 0;
}

/**
 * sched_init - initializes the scheduler subsystem
 *
 * Returns 0 if successful, or -ENOMEM if out of memory.
 */
int sched_init(void)
{
	int ret;

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

	return 0;
}
