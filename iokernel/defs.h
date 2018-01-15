/*
 * defs.h - shared definitions local to the iokernel
 */

#include <base/stddef.h>
#include <base/lrpc.h>
#include <base/mem.h>
#include <iokernel/control.h>
#include <net/ethernet.h>

/*
 * Constant limits
 */
#define IOKERNEL_MAX_PROC 1024
#define IOKERNEL_NUM_MBUFS	8191
#define IOKERNEL_PKT_BURST_SIZE	32
#define IOKERNEL_CONTROL_BURST_SIZE 8
#define IOKERNEL_CMD_BURST_SIZE 32

/*
 * Process Support
 */

struct thread {
	struct lrpc_chan_out	rxq;
	struct lrpc_chan_in		txpktq;
	struct lrpc_chan_in		txcmdq;
	pid_t					tid;
	int32_t					park_efd;
};

struct proc {
	pid_t			pid;
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
 * Dataplane state
 */
struct dataplane {
	uint8_t				port;
	struct rte_mempool	*rx_mbuf_pool;

	struct proc			*clients[IOKERNEL_MAX_PROC];
	int					nr_clients;
	struct rte_hash		*mac_to_proc;
	struct rte_hash		*pid_to_proc;
};

extern struct dataplane dp;

/*
 * Initialization
 */

extern int control_init(void);
extern int dpdk_init();
extern int rx_init();
extern int tx_init();
extern int dp_clients_init();
extern int dpdk_late_init();

/*
 * dataplane RX/TX functions
 */
extern void rx_burst();
extern void tx_burst();
extern bool tx_send_completion(void *obj);

/*
 * dataplane functions for communicating with runtimes and the control plane
 */
extern void dp_clients_rx_control_lrpcs();
extern void commands_rx();
