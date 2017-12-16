/*
 * defs.h - internal runtime definitions
 */

#pragma once

#include <base/stddef.h>
#include <base/list.h>
#include <base/mem.h>
#include <base/tcache.h>
#include <base/lrpc.h>
#include <net/ethernet.h>
#include <net/ip.h>
#include <iokernel/control.h>
#include <net/mbufq.h>
#include <runtime/thread.h>
#include <runtime/rcu.h>

/*
 * constant limits
 * TODO: make these configurable?
 */
#define RUNTIME_MAX_THREADS	100000
#define RUNTIME_STACK_SIZE	128 * KB
#define RUNTIME_GUARD_SIZE	128 * KB
#define RUNTIME_RQ_SIZE		32


/*
 * Trap frame support
 */

/*
 * See the "System V Application Binary Interface" for a full explation of
 * calling and argument passing conventions.
 */

struct thread_tf {
	/* argument registers, can be clobbered by callee */
	uint64_t rdi; /* first argument */
	uint64_t rsi;
	uint64_t rdx;
	uint64_t rcx;
	uint64_t r8;
	uint64_t r9;
	uint64_t r10;
	uint64_t r11;

	/* callee-saved registers */
	uint64_t rbx;
	uint64_t rbp;
	uint64_t r12;
	uint64_t r13;
	uint64_t r14;
	uint64_t r15;

	/* special-purpose registers */
	uint64_t rax;	/* holds return value */
	uint64_t rip;	/* instruction pointer */
	uint64_t rsp;	/* stack pointer */
};

#define ARG0(tf)        ((tf)->rdi)
#define ARG1(tf)        ((tf)->rsi)
#define ARG2(tf)        ((tf)->rdx)
#define ARG3(tf)        ((tf)->rcx)
#define ARG4(tf)        ((tf)->r8)
#define ARG5(tf)        ((tf)->r9)


/*
 * Thread support
 */

enum {
	THREAD_STATE_RUNNING = 0,
	THREAD_STATE_RUNNABLE,
	THREAD_STATE_SLEEPING,
};

struct stack;

struct thread {
	struct thread_tf	tf;
	struct list_node	link;
	struct stack		*stack;
	unsigned int		main_thread:1;
	unsigned int		state;

	/* channel state */
	void			*chan_buf;
	int			chan_closed;
};

typedef void (*runtime_fn_t)(unsigned long arg);

/* assembly helper routines from switch.S */
extern void __pop_tf(struct thread_tf *tf) __noreturn;
extern void __call_runtime(struct thread_tf *tf, runtime_fn_t fn,
			   void *stack, unsigned long arg);


/*
 * Stack support
 */

#define STACK_PTR_SIZE	(RUNTIME_STACK_SIZE / sizeof(uintptr_t))
#define GUARD_PTR_SIZE	(RUNTIME_GUARD_SIZE / sizeof(uintptr_t))

struct stack {
	uintptr_t	usable[STACK_PTR_SIZE];
	uintptr_t	guard[GUARD_PTR_SIZE]; /* unreadable and unwritable */
};

extern __thread struct tcache_perthread stack_pt;

/**
 * stack_alloc - allocates a stack
 *
 * Stack allocation is extremely cheap, think less than taking a lock.
 *
 * Returns an unitialized stack.
 */
static inline struct stack *stack_alloc(void)
{
	return tcache_alloc(&stack_pt);
}

/**
 * stack_free - frees a stack
 * @s: the stack to free
 */
static inline void stack_free(struct stack *s)
{
	return tcache_free(&stack_pt, (void *)s);
}

#define RSP_ALIGNMENT	16

static inline void assert_rsp_aligned(uint64_t rsp)
{
	/*
	 * The stack must be 16-byte aligned at process entry according to
	 * the System V Application Binary Interface (section 3.4.1).
	 *
	 * The callee assumes a return address has been pushed on the aligned
	 * stack by CALL, so we look for an 8 byte offset.
	 */
	assert(rsp % RSP_ALIGNMENT == sizeof(void *));
}

/**
 * stack_init_to_rsp - sets up an exit handler and returns the top of the stack
 * @s: the stack to initialize
 * @exit_fn: exit handler that is called when the top of the call stack returns
 *
 * Returns the top of the stack as a stack pointer.
 */
static inline uint64_t stack_init_to_rsp(struct stack *s, void (*exit_fn)(void))
{
	uint64_t rsp;

	s->usable[STACK_PTR_SIZE - 1] = (uintptr_t)exit_fn;
	rsp = (uint64_t)&s->usable[STACK_PTR_SIZE - 1];
	assert_rsp_aligned(rsp);
	return rsp;
}

/**
 * stack_init_to_rsp_with_buf - sets up an exit handler and returns the top of
 * the stack, reserving space for a buffer above
 * @s: the stack to initialize
 * @buf: a pointer to store the buffer pointer
 * @buf_len: the length of the buffer to reserve
 * @exit_fn: exit handler that is called when the top of the call stack returns
 *
 * Returns the top of the stack as a stack pointer.
 */
static inline uint64_t
stack_init_to_rsp_with_buf(struct stack *s, void **buf, size_t buf_len,
			   void (*exit_fn)(void))
{
	uint64_t rsp, pos = STACK_PTR_SIZE;

	/* reserve the buffer */
	pos -= div_up(buf_len, sizeof(uint64_t));
	pos = align_down(pos, RSP_ALIGNMENT / sizeof(uint64_t));
	*buf = (void *)&s->usable[pos];

	/* setup for usage as stack */
	s->usable[--pos] = (uintptr_t)exit_fn;
	rsp = (uint64_t)&s->usable[pos];
	assert_rsp_aligned(rsp);
	return rsp;
}

/*
 * ioqueues
 */

DECLARE_SPINLOCK(qlock);
extern unsigned int nrqs;

struct iokernel_control {
	int fd;
	mem_key_t key;
	shmptr_t next_free;
	unsigned int thread_count;
	struct thread_spec threads[NCPU];
	void *tx_buf;
	size_t tx_len;
};

extern struct iokernel_control iok;


/*
 * Per-kernel-thread State
 */

struct kthread {
	/* 1st cache-line */
	spinlock_t		lock;
	uint32_t		generation;
	uint32_t		rq_head;
	uint32_t		rq_tail;
	struct list_head	rq_overflow;
	struct lrpc_chan_in	rxq;
	unsigned long		pad;

	/* 2nd-5th cache-line */
	thread_t		*rq[RUNTIME_RQ_SIZE];

	/* 6th cache-line */
	struct lrpc_chan_out	txpktq;
	struct lrpc_chan_out	txcmdq;

	/* 7th cache-line */
	struct mbufq		txpktq_overflow;
	struct mbufq		txcmdq_overflow;
};

extern __thread struct kthread *mykthread;

/**
 * myk - returns the per-kernel-thread data
 */
static inline struct kthread *myk(void)
{
	return mykthread;
}

DECLARE_SPINLOCK(klock);
extern unsigned int nrks;
extern struct kthread *ks[NCPU];

extern void kthread_attach(void);
extern void kthread_detach(void);


/*
 * RCU support
 */

extern unsigned int rcu_gen;
extern __thread unsigned int rcu_tlgen;
extern void __rcu_schedule(void);

/**
 * rcu_schedule - called during each reschedule to advance to the next quiescent
 * period
 */
static inline void rcu_schedule(void)
{
#ifdef DEBUG
	assert(rcu_read_count == 0);
#endif /* DEBUG */

	if (unlikely(load_acquire(&rcu_gen) != rcu_tlgen))
		__rcu_schedule();
}


/*
 * Network stack
 */

struct net_cfg {
	struct shm_region	tx_region;
	struct shm_region	rx_region;
	uint32_t		addr;
	uint32_t		netmask;
	uint32_t		gateway;
	uint32_t		broadcast;
	uint32_t		network;
	struct eth_addr		mac;
	uint8_t			pad[6];
} __packed;

extern struct net_cfg netcfg;
extern int net_init(void);
extern int net_init_thread(void);
extern void net_schedule(struct kthread *k, unsigned int budget);


/*
 * init
 */

extern int kthread_init_thread(void);
extern int ioqueues_init(unsigned int threads);
extern int ioqueues_init_thread(void);
extern int stack_init_thread(void);
extern int stack_init(void);
extern int sched_init_thread(void);
extern int sched_init(void);
extern void sched_start(void) __noreturn;
extern int thread_spawn_main(thread_fn_t fn, void *arg);
