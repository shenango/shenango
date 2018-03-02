/*
 * defs.h - internal runtime definitions
 */

#pragma once

#include <ucontext.h>

#include <base/stddef.h>
#include <base/list.h>
#include <base/mem.h>
#include <base/tcache.h>
#include <base/gen.h>
#include <base/lrpc.h>
#include <base/thread.h>
#include <net/ethernet.h>
#include <net/ip.h>
#include <iokernel/control.h>
#include <net/mbufq.h>
#include <runtime/thread.h>
#include <runtime/rcu.h>
#include <runtime/preempt.h>


/*
 * constant limits
 * TODO: make these configurable?
 */

#define RUNTIME_MAX_THREADS	100000
#define RUNTIME_STACK_SIZE	128 * KB
#define RUNTIME_GUARD_SIZE	128 * KB
#define RUNTIME_RQ_SIZE		32
#define RUNTIME_NET_BUDGET	16
#define RUNTIME_MAX_TIMERS	4096
#define RUNTIME_DETACH_US	100
#define RUNTIME_PARK_POLL_US	2


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
extern void __jmp_thread(struct thread_tf *tf) __noreturn;
extern void __jmp_runtime(struct thread_tf *tf, runtime_fn_t fn,
			  void *stack, unsigned long arg);
extern void __jmp_runtime_nosave(runtime_fn_t fn, void *stack,
				 unsigned long arg) __noreturn;
extern void __jmp_restore_sigctx(ucontext_t *c,
                                 size_t fpstate_offset) __noreturn;

/*
 * Stack support
 */

#define STACK_PTR_SIZE	(RUNTIME_STACK_SIZE / sizeof(uintptr_t))
#define GUARD_PTR_SIZE	(RUNTIME_GUARD_SIZE / sizeof(uintptr_t))

struct stack {
	uintptr_t	usable[STACK_PTR_SIZE];
	uintptr_t	guard[GUARD_PTR_SIZE]; /* unreadable and unwritable */
};

DECLARE_PERTHREAD(struct tcache_perthread, stack_pt);

extern __thread struct stack *signal_stack;

/**
 * stack_alloc - allocates a stack
 *
 * Stack allocation is extremely cheap, think less than taking a lock.
 *
 * Returns an unitialized stack.
 */
static inline struct stack *stack_alloc(void)
{
	return tcache_alloc(&perthread_get(stack_pt));
}

/**
 * stack_free - frees a stack
 * @s: the stack to free
 */
static inline void stack_free(struct stack *s)
{
	tcache_free(&perthread_get(stack_pt), (void *)s);
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

/*
 * These are per-kthread stat counters. It's recommended that most counters be
 * monotonically increasing, as that decouples the counters from any particular
 * collection time period. However, it may not be possible to represent all
 * counters this way.
 *
 * Don't use these enums directly. Instead, use the STAT() macro.
 */
enum {
	/* scheduler counters */
	STAT_RESCHEDULES = 0,
	STAT_SCHED_CYCLES,
	STAT_PROGRAM_CYCLES,
	STAT_THREADS_STOLEN,
	STAT_NETS_STOLEN,
	STAT_TIMERS_STOLEN,
	STAT_NETS_LOCAL,
	STAT_TIMERS_LOCAL,
	STAT_PARKS,
	STAT_PREEMPTIONS,

	/* network stack counters */
	STAT_RX_BYTES,
	STAT_RX_PACKETS,
	STAT_TX_BYTES,
	STAT_TX_PACKETS,
	STAT_DROPS,

	/* total number of counters */
	STAT_NR,
};

struct timer_idx;

struct kthread {
	/* 1st cache-line */
	spinlock_t		lock;
	uint32_t		generation;
	uint32_t		rq_head;
	uint32_t		rq_tail;
	struct list_head	rq_overflow;
	struct lrpc_chan_in	rxq;
	int			park_efd;
	unsigned int		parked:1;
	unsigned int		detached:1;
	unsigned int		preempted:1;

	/* 2nd cache-line */
	struct gen_num		rq_gen;
	struct mbufq		txpktq_overflow;
	struct mbufq		txcmdq_overflow;
	unsigned int		rcu_gen;
	unsigned int		pad[1];
	uint64_t		park_us;

	/* 3rd cache-line */
	struct lrpc_chan_out	txpktq;
	struct lrpc_chan_out	txcmdq;

	/* 4th-7th cache-line */
	thread_t		*rq[RUNTIME_RQ_SIZE];

	/* 8th cache-line */
	spinlock_t		timer_lock;
	unsigned int		timern;
	struct timer_idx	*timers;
	unsigned long		pad2[6];

	/* 9th cache-line, statistics counters */
	uint64_t		stats[STAT_NR];

	/* cold-data this point onward */
	thread_t		*preempted_th;
	ucontext_t		preempted_uctx;
	size_t			fpstate_offset;
};

/* compile-time verification of cache-line alignment */
BUILD_ASSERT(offsetof(struct kthread, lock) % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(struct kthread, rq_gen) % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(struct kthread, txpktq) % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(struct kthread, rq) % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(struct kthread, timer_lock) % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(struct kthread, stats) % CACHE_LINE_SIZE == 0);

extern __thread struct kthread *mykthread;

/**
 * myk - returns the per-kernel-thread data
 */
static inline struct kthread *myk(void)
{
	return mykthread;
}

/**
 * getk - returns the per-kernel-thread data and disables preemption
 *
 * WARNING: If you're using myk() instead of getk(), that's a bug if preemption
 * is enabled. The local kthread can change at anytime.
 */
static inline struct kthread *getk(void)
{
	preempt_disable();
	return mykthread;
}

/**
 * putk - reenables preemption after calling getk()
 */
static inline void putk(void)
{
	preempt_enable();
}

DECLARE_SPINLOCK(klock);
extern unsigned int maxks;
extern unsigned int spinks;
extern unsigned int guaranteedks;
extern unsigned int nrks;
extern struct kthread *ks[NCPU];

extern void kthread_detach(struct kthread *r);
extern void kthread_park(bool voluntary);
extern void kthread_wait_to_attach(void);

/**
 * STAT - gets a stat counter
 *
 * e.g. STAT(DROPS)++;
 *
 * Deliberately could race with preemption.
 */
#define STAT(counter) (myk()->stats[STAT_ ## counter])


/*
 * RCU support
 */

extern unsigned int rcu_gen;
extern void __rcu_recurrent(struct kthread *k);
extern void rcu_detach(struct kthread *k, unsigned int rgen);

/**
 * rcu_poll - advances to the next quiescent period
 *
 * Called during each schedule() invocation.
 */
static inline void rcu_recurrent(void)
{
	struct kthread *k = myk();

#ifdef DEBUG
	assert(rcu_read_count == 0);
#endif /* DEBUG */

	if (unlikely(load_acquire(&rcu_gen) != k->rcu_gen))
		__rcu_recurrent(k);
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
	struct eth_addr		mac;
	uint8_t			pad[14];
} __packed;

BUILD_ASSERT(sizeof(struct net_cfg) == CACHE_LINE_SIZE);

extern struct net_cfg netcfg;

extern thread_t *net_run(struct kthread *k, unsigned int budget);
extern void __net_recurrent(void);

/**
 * net_recurrent - flush overflow packets
 *
 * Called during each schedule() invocation and during TX.
 */
static inline void net_recurrent(void)
{
	struct kthread *k = myk();

	if (!mbufq_empty(&k->txpktq_overflow) ||
	    !mbufq_empty(&k->txcmdq_overflow))
		__net_recurrent();
}


/*
 * Timer support
 */

extern thread_t *timer_run(struct kthread *k);


/*
 * Preemption support
 */

extern void preempt_reenter(ucontext_t *c, size_t fpstate_offset) __noreturn;


/*
 * Init
 */

/* per-thread initialization */
extern int kthread_init_thread(void);
extern int ioqueues_init_thread(void);
extern int stack_init_thread(void);
extern int timer_init_thread(void);
extern int sched_init_thread(void);
extern int stat_init_thread(void);
extern int net_init_thread(void);

/* global initialization */
extern int ioqueues_init(unsigned int threads);
extern int stack_init(void);
extern int sched_init(void);
extern int preempt_init(void);
extern int net_init(void);
extern int arp_init(void);
extern int udp_init(void);

/* late initialization */
extern int ioqueues_register_iokernel(void);
extern int arp_init_late(void);
extern int stat_init_late(void);

/* configuration loading */
extern int cfg_load(const char *path);

/* runtime entry helpers */
extern void sched_start(void) __noreturn;
extern void sched_make_uctx(ucontext_t *c);
extern int thread_spawn_main(thread_fn_t fn, void *arg);
