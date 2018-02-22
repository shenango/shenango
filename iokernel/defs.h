/*
 * defs.h - shared definitions local to the iokernel
 */

#include <base/bitmap.h>
#include <base/gen.h>
#include <base/lrpc.h>
#include <base/mem.h>
#include <base/stddef.h>
#include <iokernel/control.h>
#include <net/ethernet.h>

#include "ref.h"

/*
 * Constant limits
 */
#define IOKERNEL_MAX_PROC		1024
#define IOKERNEL_NUM_MBUFS		8191
#define IOKERNEL_TX_BURST_SIZE		64
#define IOKERNEL_CMD_BURST_SIZE		64
#define IOKERNEL_RX_BURST_SIZE		64
#define IOKERNEL_CONTROL_BURST_SIZE	4
#define IOKERNEL_RX_WAKE_THRESH		64


/*
 * Process Support
 */

struct proc;

struct thread {
	struct proc		*p;
	unsigned int		parked:1;
	struct lrpc_chan_out	rxq;
	struct lrpc_chan_in	txpktq;
	struct lrpc_chan_in	txcmdq;
	pid_t			tid;
	int32_t			park_efd;
	struct gen_num		rq_gen;
	uint32_t		last_send_tail;
	/* only valid if this thread's bit in available_threads is not set */
	unsigned int		core;
	/* the @ts index (if active) */
	unsigned int		ts_idx;
	/* the proc->active_threads index (if active) */
	unsigned int		at_idx;
};

struct proc {
	pid_t			pid;
	struct shm_region	region;
	bool			removed;
	struct ref		ref;
	bool			kill; /* the proc is being torn down */

	/* scheduler data */
	struct sched_spec	sched_cfg;

	/* runtime threads */
	unsigned int		thread_count;
	unsigned int		active_thread_count;
	struct thread		threads[NCPU];
	struct thread		*active_threads[NCPU];
	DEFINE_BITMAP(available_threads, NCPU);

	/* network data */
	struct eth_addr		mac;

	/* next pending timer, only valid if pending_timer is true */
	bool			pending_timer;
	uint64_t		deadline_us;
	unsigned int		timer_idx;

	/* table of physical addresses for shared memory */
	physaddr_t		page_paddrs[];
};

extern void proc_release(struct ref *r);

/**
 * proc_get - increments the proc reference count
 * @p: the proc to reference count
 *
 * Returns @p.
 */
static inline struct proc *proc_get(struct proc *p)
{
	ref_get(&p->ref);
	return p;
}

/**
 * proc_put - decrements the proc reference count, freeing if zero
 * @p: the proc to unreference count
 */
static inline void proc_put(struct proc *p)
{
	ref_put(&p->ref, proc_release);
}

/* the number of active threads to be polled (across all procs) */
extern unsigned int nrts;
/* an array of active threads to be polled (across all procs) */
extern struct thread *ts[NCPU];

/**
 * poll_thread - adds a thread to the queue polling array
 * @th: the thread to poll
 *
 * Can be called more than once.
 */
static inline void poll_thread(struct thread *th)
{
	if (th->ts_idx != -1)
		return;
	proc_get(th->p);
	ts[nrts] = th;
	th->ts_idx = nrts++;
}

/**
 * unpoll_thread - removes a thread from the queue polling array
 * @th: the thread to no longer poll
 */
static inline void unpoll_thread(struct thread *th)
{
	if (th->ts_idx == -1)
		return;
	ts[th->ts_idx] = ts[--nrts];
	ts[th->ts_idx]->ts_idx = th->ts_idx;
	th->ts_idx = -1;
	proc_put(th->p);
}

/*
 * Communication between control plane and data-plane in the I/O kernel
 */
#define CONTROL_DATAPLANE_QUEUE_SIZE	128
struct lrpc_params {
	struct lrpc_msg *buffer;
	uint32_t *wb;
};
extern struct lrpc_params lrpc_control_to_data_params;
extern struct lrpc_params lrpc_data_to_control_params;

/*
 * Commands from control plane to dataplane.
 */
enum {
	DATAPLANE_ADD_CLIENT,		/* points to a struct proc */
	DATAPLANE_REMOVE_CLIENT,	/* points to a struct proc */
	DATAPLANE_NR,			/* number of commands */
};

/*
 * Commands from dataplane to control plane.
 */
enum {
	CONTROL_PLANE_REMOVE_CLIENT,	/* points to a struct proc */
	CONTROL_PLANE_NR,		/* number of commands */
};

/*
 * Dataplane state
 */
struct dataplane {
	uint8_t			port;
	struct rte_mempool	*rx_mbuf_pool;

	struct proc		*clients[IOKERNEL_MAX_PROC];
	int			nr_clients;
	struct rte_hash		*mac_to_proc;
};

extern struct dataplane dp;

/*
 * Logical cores assigned to linux and the control and dataplane threads
 */
struct core_assignments {
	uint8_t linux_core;
	uint8_t ctrl_core;
	uint8_t dp_core;
};

extern struct core_assignments core_assign;

/*
 * Initialization
 */

extern int cores_init(void);
extern int control_init(void);
extern int dpdk_init();
extern int rx_init();
extern int tx_init();
extern int dp_clients_init();
extern int dpdk_late_init();

/*
 * dataplane RX/TX functions
 */
extern bool rx_burst();
extern bool tx_burst();
extern bool tx_send_completion(void *obj);

/*
 * other dataplane functions
 */
extern void dp_clients_rx_control_lrpcs();
extern bool commands_rx();
extern void dpdk_print_eth_stats();

/*
 * functions for manipulating core assignments
 */
extern void cores_init_proc(struct proc *p);
extern void cores_free_proc(struct proc *p);
extern int cores_pin_thread(pid_t tid, int core);
extern void cores_park_kthread(struct thread *t, bool force);
extern struct thread *cores_wake_kthread(struct proc *p);
extern void cores_adjust_assignments();
