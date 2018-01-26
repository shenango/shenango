/*
 * commands.c - dataplane commands to/from runtimes
 */

#include <rte_mbuf.h>

#include <base/log.h>
#include <base/lrpc.h>
#include <iokernel/queue.h>

#include "defs.h"

static int commands_drain_queue(struct proc *p, int j, struct lrpc_chan_in *l,
				struct rte_mbuf **bufs, int n)
{
	int i, n_bufs = 0;

	for (i = 0; i < n; i++) {
		uint64_t cmd;
		unsigned long payload;

		if (!lrpc_recv(l, &cmd, &payload))
			break;

		switch (cmd) {
		case TXCMD_NET_COMPLETE:
			bufs[n_bufs++] = (struct rte_mbuf *)payload;
			/* TODO: validate pointer @buf */
			break;

		case TXCMD_NET_PARKING:
			cores_park_kthread(p, j);
			break;

		default:
			/* kill the runtime? */
			BUG();
		}
	}

	return n_bufs;
}

/*
 * Process a batch of commands from runtimes.
 */
void commands_rx(void)
{
	struct rte_mbuf *bufs[IOKERNEL_CMD_BURST_SIZE];
	struct proc *p;
	struct thread *t;
	uint16_t i, j, n_bufs = 0;

	/*
	 * Poll each thread in each runtime until all have been polled or we
	 * have processed CMD_BURST_SIZE commands. TODO: maintain state across
	 * calls to this function to avoid starving threads/runtimes with higher
	 * indices.
	 */
	for (i = 0; i < dp.nr_clients; i++) {
		p = dp.clients[i];
		for (j = 0; j < p->thread_count; j++) {
			t = &p->threads[j];
			n_bufs += commands_drain_queue(p, j, &t->txcmdq,
					&bufs[n_bufs],
					IOKERNEL_CMD_BURST_SIZE - n_bufs);
			if (n_bufs >= IOKERNEL_CMD_BURST_SIZE)
				goto done_polling;
		}
	}

done_polling:
	for (i = 0; i < n_bufs; i++)
		rte_pktmbuf_free(bufs[i]);
}
