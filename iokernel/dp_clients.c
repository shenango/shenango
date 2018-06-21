/*
 * dp_clients.c - functions for registering/unregistering dataplane clients
 */

#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_lcore.h>

#include <base/log.h>
#include <base/lrpc.h>

#include "defs.h"

#define MAC_TO_PROC_ENTRIES	128

static struct lrpc_chan_out lrpc_data_to_control;
static struct lrpc_chan_in lrpc_control_to_data;

/*
 * Add a new client.
 */
static void dp_clients_add_client(struct proc *p)
{
	int ret;
	p->kill = false;
	dp.clients[dp.nr_clients++] = p;
	dp.idx_to_proc[p->permanent_index] = p;

	ret = rte_eth_dev_mac_addr_add(dp.port, (struct ether_addr *)&p->mac, 0);
	if (unlikely(ret)) {
		log_err("Failed to add mac, ret = %d", ret);
	}

	cores_init_proc(p);
}

void proc_release(struct ref *r)
{
	struct proc *p = container_of(r, struct proc, ref);
	if (!lrpc_send(&lrpc_data_to_control, CONTROL_PLANE_REMOVE_CLIENT,
			(unsigned long) p))
		log_err("dp_clients: failed to inform control of client removal");
}

/*
 * Remove a client. Notify control plane once removal is complete so that it
 * can delete its data structures.
 */
static void dp_clients_remove_client(struct proc *p)
{
	int i;

	for (i = 0; i < dp.nr_clients; i++) {
		if (dp.clients[i] == p)
			break;
	}

	if (i == dp.nr_clients) {
		WARN();
		return;
	}

	dp.idx_to_proc[p->permanent_index] = NULL;

	dp.clients[i] = dp.clients[dp.nr_clients - 1];
	dp.nr_clients--;

	rte_eth_dev_mac_addr_remove(dp.port, (struct ether_addr *)&p->mac);

	/* TODO: free queued packets/commands? */

	/* release cores assigned to this runtime */
	p->kill = true;
	cores_free_proc(p);
	proc_put(p);
}

/*
 * Process a batch of messages from the control plane.
 */
void dp_clients_rx_control_lrpcs()
{
	uint64_t cmd;
	unsigned long payload;
	uint16_t n_rx = 0;
	struct proc *p;

	while (lrpc_recv(&lrpc_control_to_data, &cmd, &payload)
			&& n_rx < IOKERNEL_CONTROL_BURST_SIZE) {
		p = (struct proc *) payload;

		switch (cmd)
		{
		case DATAPLANE_ADD_CLIENT:
			dp_clients_add_client(p);
			break;
		case DATAPLANE_REMOVE_CLIENT:
			dp_clients_remove_client(p);
			break;
		default:
			log_err("dp_clients: received unrecognized command %lu", cmd);
		}

		n_rx++;
	}
}

/*
 * Initialize channels for communicating with the I/O kernel control plane.
 */
int dp_clients_init(void)
{
	int ret;

	ret = lrpc_init_in(&lrpc_control_to_data,
			lrpc_control_to_data_params.buffer, CONTROL_DATAPLANE_QUEUE_SIZE,
			lrpc_control_to_data_params.wb);
	if (ret < 0) {
		log_err("dp_clients: initializing LRPC from control plane failed");
		return -1;
	}

	ret = lrpc_init_out(&lrpc_data_to_control,
			lrpc_data_to_control_params.buffer, CONTROL_DATAPLANE_QUEUE_SIZE,
			lrpc_data_to_control_params.wb);
	if (ret < 0) {
		log_err("dp_clients: initializing LRPC to control plane failed");
		return -1;
	}

	dp.nr_clients = 0;
	memset(dp.idx_to_proc, 0, sizeof(dp.idx_to_proc));

	return 0;
}
