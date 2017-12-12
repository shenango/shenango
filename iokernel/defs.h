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
#define IOKERNEL_MAX_PROC 1024

struct thread {
	struct lrpc_chan_out	rxq;
	struct lrpc_chan_in	txpktq;
	struct lrpc_chan_in	txcmdq;
};

struct proc {
	pid_t			pid;
	mem_key_t		key;
	struct shm_region	region;
	bool			removed;

	/* scheduler data */
	struct sched_spec	sched_cfg;

	/* runtime threads */
	unsigned int		thread_count;
	struct thread		threads[NCPU];

	/* network data */
	struct eth_addr		mac;

	/* table of physical addresses for shared memory */
	physaddr_t		page_paddrs[];
};

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
	CONTROL_PLANE_NR,				/* number of commands */
};

/*
 * Initialization
 */

extern int control_init(void);
extern int dpdk_init(uint8_t port);

/*
 * DPDK functions
 */
extern void dpdk_loop(uint8_t port) __noreturn;
extern bool dpdk_send_completion(void *buf);
