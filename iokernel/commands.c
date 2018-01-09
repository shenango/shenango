/*
 * commands.c - dataplane commands to/from runtimes
 */

#include <rte_mbuf.h>

#include <base/log.h>
#include <base/lrpc.h>
#include <iokernel/queue.h>

#include "defs.h"

/*
 * Process a batch of commands from runtimes.
 */
void commands_rx()
{
	uint16_t i, j, n_cmds;
	struct proc *p;
	struct thread *t;
	uint64_t cmd;
	unsigned long payload;
	struct rte_mbuf *buf;

	/* Poll each thread in each runtime until all have been polled or we have
	 * processed CMD_BURST_SIZE commands. TODO: maintain state across calls to
	 * this function to avoid starving threads/runtimes with higher indices. */
	n_cmds = 0;
	for (i = 0; i < dp.nr_clients; i++) {
		p = dp.clients[i];
		for (j = 0; j < p->thread_count; j++) {
			t = &p->threads[j];
			if (lrpc_recv(&t->txcmdq, &cmd, &payload)) {
				if (cmd == TXCMD_NET_COMPLETE) {
					/* get pointer to struct rte_mbuf, return to mempool */
					buf = (struct rte_mbuf *)payload;
					rte_pktmbuf_free(buf);
				} else
					log_err("commands: TXCMD %lu not handled", cmd);

				n_cmds++;
				if (n_cmds >= IOKERNEL_CMD_BURST_SIZE)
					return;
			}
		}
	}
}
