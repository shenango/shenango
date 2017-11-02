/*
 * defs.h - shared definitions local to the iokernel
 */

#include <base/stddef.h>
#include <base/lrpc.h>
#include <base/bitmap.h>
#include <base/mem.h>
#include <iokernel/control.h>


/*
 * Process Support
 */

struct proc {
	pid_t			pid;
	mem_key_t		key;
	struct shm_region	region;
	struct control_status	*status;
	DEFINE_BITMAP(core_mask, NCPU);

	/* RX and TX queues */
	unsigned int		rx_pkt_count;
	unsigned int		rx_cmd_count;
	unsigned int		tx_count;
	unsigned int		pad;
	struct lrpc_chan_rx	*cpu_to_rx_pkt[NCPU];
	struct lrpc_chan_rx	*cpu_to_rx_cmd[NCPU];
	struct lrpc_chan_tx	*cpu_to_tx[NCPU];
	struct lrpc_chan_rx	rx_pkt[NCPU];
	struct lrpc_chan_rx	rx_cmd[NCPU];
	struct lrpc_chan_tx	tx[NCPU];

	/* scheduler data */
	struct control_sched_config cfg;
};


/*
 * Initialization
 */

extern int control_init(void);
