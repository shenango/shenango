/*
 * defs.h - shared definitions local to the iokernel
 */

#include <base/stddef.h>
#include <base/lrpc.h>
#include <base/mem.h>
#include <iokernel/control.h>
#include <net/ethernet.h>


/*
 * Process Support
 */

struct thread {
	struct lrpc_chan_out	rxq;
	struct lrpc_chan_in	txpktq;
	struct lrpc_chan_in	txcmdq;
};

struct proc {
	pid_t			pid;
	mem_key_t		key;
	struct shm_region	region;

	/* scheduler data */
	struct sched_spec	sched_cfg;

	/* runtime threads */
	unsigned int		thread_count;
	struct thread		threads[NCPU];

	/* network data */
	struct eth_addr		mac;
};


/*
 * Initialization
 */

extern int control_init(void);
extern int dpdk_init(uint8_t port);

/*
 * DPDK main loop
 */

extern void dpdk_run(uint8_t port) __noreturn;
