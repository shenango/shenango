/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * dpdk.c - the data-plane for the I/O kernel
 */

#include <stdint.h>
#include <inttypes.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_ip.h>
#include <rte_jhash.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include <base/log.h>
#include <base/mem.h>
#include <iokernel/queue.h>
#include <iokernel/shm.h>

#include "defs.h"

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define PKT_BURST_SIZE 32
#define CONTROL_BURST_SIZE 8
#define CMD_BURST_SIZE 32
#define MAC_TO_PROC_ENTRIES	128

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
			.max_rx_pkt_len = ETHER_MAX_LEN,
			.hw_ip_checksum = 1,
	}
};
static struct shm_region ingress_mbuf_region;
static struct lrpc_chan_out lrpc_data_to_control;
static struct lrpc_chan_in lrpc_control_to_data;
static struct proc *clients[IOKERNEL_MAX_PROC];
static int nr_clients = 0;
struct rte_mempool *egress_mbuf_pool;
static struct rte_hash *mac_to_proc;

/*
 * Private data stored in egress mbufs, used to send completions to runtimes.
 */
struct egress_pktmbuf_priv {
	struct thread *thread;
	unsigned long completion_data;
};

static inline struct egress_pktmbuf_priv *egress_get_priv(struct rte_mbuf *buf)
{
	return (struct egress_pktmbuf_priv *) (((char *) buf)
			+ sizeof(struct rte_mbuf));
}

/*
 * Callback to unmap the shared memory used by a mempool when destroying it.
 */
static void dpdk_mempool_memchunk_free(struct rte_mempool_memhdr *memhdr,
		void *opaque)
{
	mem_unmap_shm(opaque);
}

/*
 * Create and initialize a packet mbuf pool in shared memory, based on
 * rte_pktmbuf_pool_create.
 */
static struct rte_mempool *dpdk_pktmbuf_pool_create_in_shm(const char *name,
		unsigned n, unsigned cache_size, uint16_t priv_size,
		uint16_t data_room_size, int socket_id)
{
	unsigned elt_size;
	struct rte_pktmbuf_pool_private mbp_priv;
	struct rte_mempool *mp;
	int ret;
	void *shbuf;
	size_t total_elt_sz, pg_size, pg_shift, len;

	/* create rte_mempool */
	if (RTE_ALIGN(priv_size, RTE_MBUF_PRIV_ALIGN) != priv_size) {
		log_err("dpdk: mbuf priv_size=%u is not aligned", priv_size);
		goto fail;
	}
	elt_size = sizeof(struct rte_mbuf) + (unsigned) priv_size
			+ (unsigned) data_room_size;
	mbp_priv.mbuf_data_room_size = data_room_size;
	mbp_priv.mbuf_priv_size = priv_size;

	mp = rte_mempool_create_empty(name, n, elt_size, cache_size,
			sizeof(struct rte_pktmbuf_pool_private), socket_id, 0);
	if (mp == NULL)
		goto fail;

	ret = rte_mempool_set_ops_byname(mp, RTE_MBUF_DEFAULT_MEMPOOL_OPS, NULL);
	if (ret != 0) {
		log_err("dpdk: error setting mempool handler");
		goto fail_free_mempool;
	}
	rte_pktmbuf_pool_init(mp, &mbp_priv);

	/* check necessary size and map shared memory */
	total_elt_sz = mp->header_size + mp->elt_size + mp->trailer_size;
	pg_size = PGSIZE_2MB;
	pg_shift = rte_bsf32(pg_size);
	len = rte_mempool_xmem_size(n, total_elt_sz, pg_shift);
	if (len > INGRESS_MBUF_SHM_SIZE) {
		log_err("dpdk: shared memory is too small for number of mbufs");
		goto fail_free_mempool;
	}

	shbuf = mem_map_shm(INGRESS_MBUF_SHM_KEY, NULL, INGRESS_MBUF_SHM_SIZE,
			pg_size, true);
	if (shbuf == MAP_FAILED) {
		log_err("dpdk: mem_map_shm failed");
		goto fail_free_mempool;
	}
	ingress_mbuf_region.base = shbuf;
	ingress_mbuf_region.len = len;

	/* populate mempool using shared memory */
	ret = rte_mempool_populate_virt(mp, shbuf, len, pg_size,
			dpdk_mempool_memchunk_free, shbuf);
	if (ret < 0) {
		log_err("dpdk: error populating mempool %d", ret);
		goto fail_unmap_memory;
	}

	rte_mempool_obj_iter(mp, rte_pktmbuf_init, NULL);

	return mp;

fail_unmap_memory:
	mem_unmap_shm(shbuf);
fail_free_mempool:
	rte_mempool_free(mp);
fail:
	log_err("dpdk: couldn't create pktmbuf pool %s", name);
	return NULL;
}

/*
 * Create and initialize a packet mbuf pool for holding struct mbufs and
 * handling completion events. Actual buffer memory is separate, in shared
 * memory.
 */
static struct rte_mempool *dpdk_pktmbuf_completion_pool_create(const char *name,
		unsigned n, uint16_t priv_size, int socket_id)
{
	struct rte_mempool *mp;
	struct rte_pktmbuf_pool_private mbp_priv;
	unsigned elt_size;
	int ret;

	if (RTE_ALIGN(priv_size, RTE_MBUF_PRIV_ALIGN) != priv_size) {
		RTE_LOG(ERR, MBUF, "mbuf priv_size=%u is not aligned\n",
			priv_size);
		rte_errno = EINVAL;
		return NULL;
	}
	elt_size = sizeof(struct rte_mbuf) + (unsigned)priv_size;
	mbp_priv.mbuf_data_room_size = 0;
	mbp_priv.mbuf_priv_size = priv_size;

	mp = rte_mempool_create_empty(name, n, elt_size, 0,
		 sizeof(struct rte_pktmbuf_pool_private), socket_id, 0);
	if (mp == NULL)
		return NULL;

	ret = rte_mempool_set_ops_byname(mp, "completion", NULL);
	if (ret != 0) {
		RTE_LOG(ERR, MBUF, "error setting mempool handler\n");
		rte_mempool_free(mp);
		rte_errno = -ret;
		return NULL;
	}
	rte_pktmbuf_pool_init(mp, &mbp_priv);

	ret = rte_mempool_populate_default(mp);
	if (ret < 0) {
		rte_mempool_free(mp);
		rte_errno = -ret;
		return NULL;
	}

	rte_mempool_obj_iter(mp, rte_pktmbuf_init, NULL);

	return mp;
}

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int dpdk_port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf;

	if (port >= rte_eth_dev_count())
		return -1;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	/* Enable TX offloading */
	rte_eth_dev_info_get(0, &dev_info);
	txconf = &dev_info.default_txconf;
	txconf->txq_flags &= ~(ETH_TXQ_FLAGS_NOXSUMUDP |
			ETH_TXQ_FLAGS_NOXSUMTCP);

	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), txconf);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}

/*
 * Swap source and destination MAC addresses.
 */
void dpdk_swap_ether_src_dest(struct rte_mbuf *buf)
{
	struct ether_hdr *ptr_mac_hdr;
	struct ether_addr src_addr;

	ptr_mac_hdr = rte_pktmbuf_mtod(buf, struct ether_hdr *);
	ether_addr_copy(&ptr_mac_hdr->s_addr, &src_addr);
	ether_addr_copy(&ptr_mac_hdr->d_addr, &ptr_mac_hdr->s_addr);
	ether_addr_copy(&src_addr, &ptr_mac_hdr->d_addr);
}

/*
 * Swap source and destination IP addresses.
 */
void dpdk_swap_ip_src_dest(struct rte_mbuf *buf)
{
	struct ether_hdr *ptr_mac_hdr;
	uint16_t ether_type;
	struct ipv4_hdr *ptr_ipv4_hdr;
	uint32_t src_addr;

	/* Check that this is IPv4. TODO: support IPv6. */
	ptr_mac_hdr = rte_pktmbuf_mtod(buf, struct ether_hdr *);
	ether_type = ptr_mac_hdr->ether_type;
	if (ether_type != rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
		printf("WARNING: ether type %d is not supported\n", ether_type);
		return;
	}

	ptr_ipv4_hdr = rte_pktmbuf_mtod_offset(buf, struct ipv4_hdr *,
			sizeof(struct ether_hdr));
	src_addr = ptr_ipv4_hdr->src_addr;
	ptr_ipv4_hdr->src_addr = ptr_ipv4_hdr->dst_addr;
	ptr_ipv4_hdr->dst_addr = src_addr;
}

/*
 * Prepend rx_net_hdr preamble to ingress packets.
 */
static struct rx_net_hdr *dpdk_prepend_rx_preamble(struct rte_mbuf *buf)
{
	struct rx_net_hdr *net_hdr;
	uint64_t masked_ol_flags;

	net_hdr = (struct rx_net_hdr *) rte_pktmbuf_prepend(buf,
			(uint16_t) sizeof(*net_hdr));
	RTE_ASSERT(net_hdr != NULL);

	net_hdr->completion_data = (unsigned long)buf;
	net_hdr->len = rte_pktmbuf_pkt_len(buf) - sizeof(*net_hdr);
	net_hdr->rss_hash = 0; /* unused for now */
	masked_ol_flags = buf->ol_flags & PKT_RX_IP_CKSUM_MASK;
	if (masked_ol_flags == PKT_RX_IP_CKSUM_GOOD)
		net_hdr->csum_type = CHECKSUM_TYPE_UNNECESSARY;
	else
		net_hdr->csum_type = CHECKSUM_TYPE_NEEDED;
	net_hdr->csum = 0; /* unused for now */

	return net_hdr;
}

/*
 * Prepare rte_mbuf struct for transmission.
 */
static void dpdk_prepare_tx_mbuf(struct rte_mbuf *buf,
		struct tx_net_hdr *net_hdr, struct proc *p, struct thread *thread)
{
	uint32_t page_number;
	struct egress_pktmbuf_priv *priv_data;

	/* initialize mbuf to point to net_hdr->payload */
	buf->buf_addr = (char *) net_hdr->payload;
	page_number = PGN_2MB((uintptr_t) buf->buf_addr -
			(uintptr_t) p->region.base);
	buf->buf_physaddr = p->page_paddrs[page_number] + PGOFF_2MB(buf->buf_addr);
	buf->data_off = 0;
	rte_mbuf_refcnt_set(buf, 1);

	buf->buf_len = net_hdr->len;
	buf->pkt_len = net_hdr->len;
	buf->data_len = net_hdr->len;

	buf->ol_flags = 0;
	if (net_hdr->olflags != 0) {
		if (net_hdr->olflags & OLFLAG_IP_CHKSUM)
			buf->ol_flags |= PKT_TX_IP_CKSUM;
		if (net_hdr->olflags & OLFLAG_TCP_CHKSUM)
			buf->ol_flags |= PKT_TX_TCP_CKSUM;
		if (net_hdr->olflags & OLFLAG_IPV4)
			buf->ol_flags |= PKT_TX_IPV4;
		if (net_hdr->olflags & OLFLAG_IPV6)
			buf->ol_flags |= PKT_TX_IPV6;

		buf->l2_len = ETHER_HDR_LEN;
		buf->l3_len = sizeof(struct ipv4_hdr);
	}

	/* initialize the private data, used to send completion events */
	priv_data = egress_get_priv(buf);
	priv_data->thread = thread;
	priv_data->completion_data = net_hdr->completion_data;
}

/*
 * Send a packet up to a runtime. Return true if successful, false otherwise.
 */
static bool dpdk_enqueue_to_runtime(struct rx_net_hdr *net_hdr, struct proc *p)
{
	struct thread *t;
	shmptr_t shmptr;

	/* choose a random thread */
	t = &p->threads[rand() % p->thread_count];
	shmptr = ptr_to_shmptr(&ingress_mbuf_region, net_hdr,
			sizeof(struct rx_net_hdr));

	return lrpc_send(&t->rxq, RX_NET_RECV, shmptr);
}

/*
 * Send a completion event to the runtime for the mbuf pointed to by obj.
 */
bool dpdk_send_completion(void *obj) {
	struct rte_mbuf *buf;
	struct egress_pktmbuf_priv *priv_data;
	struct thread *t;

	if (unlikely(nr_clients == 0))
		return true;

	/* TODO: verify that this proc is still registered */

	buf = (struct rte_mbuf *) obj;
	priv_data = egress_get_priv(buf);
	t = priv_data->thread;
	if (!lrpc_send(&t->rxq, RX_NET_COMPLETE, priv_data->completion_data)) {
		log_warn("dpdk: failed to enqueue completion event to runtime");
		return false;
	}

	return true;
}

/*
 * Process a batch of incoming packets.
 */
static void dpdk_rx_burst(uint8_t port)
{
	struct rte_mbuf *bufs[PKT_BURST_SIZE];
	uint16_t nb_rx, i, j, n_sent;
	struct rte_mbuf *buf;
	struct ether_hdr *ptr_mac_hdr;
	struct ether_addr *ptr_dst_addr;
	int ret;
	void *data;
	struct proc *p;
	struct rx_net_hdr *net_hdr;
	bool success;

	/* retrieve packets from NIC queue */
	nb_rx = rte_eth_rx_burst(port, 0, bufs, PKT_BURST_SIZE);
	if (nb_rx > 0)
		log_debug("dpdk: received %d packets on port %d", nb_rx, port);

	for (i = 0; i < nb_rx; i++) {
		/* parse dst ether addr */
		buf = bufs[i];

		ptr_mac_hdr = rte_pktmbuf_mtod(buf, struct ether_hdr *);
		ptr_dst_addr = &ptr_mac_hdr->d_addr;
		log_debug("dpdk: rx packet with MAC %02" PRIx8 " %02" PRIx8 " %02"
				PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8,
				ptr_dst_addr->addr_bytes[0], ptr_dst_addr->addr_bytes[1],
				ptr_dst_addr->addr_bytes[2], ptr_dst_addr->addr_bytes[3],
				ptr_dst_addr->addr_bytes[4], ptr_dst_addr->addr_bytes[5]);

		if (is_unicast_ether_addr(ptr_dst_addr)) {
			/* lookup runtime by MAC in hash table */
			ret = rte_hash_lookup_data(mac_to_proc,
					&ptr_dst_addr->addr_bytes[0], &data);
			if (ret < 0) {
				log_warn("dpdk: received packet for unregistered MAC");
				rte_pktmbuf_free(buf);
				continue;
			}

			p = (struct proc *) data;
			net_hdr = dpdk_prepend_rx_preamble(buf);
			if (!dpdk_enqueue_to_runtime(net_hdr, p)) {
				log_warn("dpdk: failed to enqueue unicast packet to runtime");
				rte_pktmbuf_free(buf);
			}
		} else if (is_broadcast_ether_addr(ptr_dst_addr) && nr_clients > 0) {
			/* forward to all registered runtimes */
			net_hdr = dpdk_prepend_rx_preamble(buf);

			n_sent = 0;
			for (j = 0; j < nr_clients; j++) {
				success = dpdk_enqueue_to_runtime(net_hdr, clients[j]);
				if (success)
					n_sent++;
				else
					log_warn("dpdk: failed to enqueue broadcast packet to "
							"runtime");
			}

			if (n_sent == 0)
				rte_pktmbuf_free(buf);
			else
				rte_mbuf_refcnt_update(buf, n_sent - 1);
		} else {
			log_warn("dpdk: unhandled packet with MAC %x %x %x %x %x %x",
					ptr_dst_addr->addr_bytes[0], ptr_dst_addr->addr_bytes[1],
					ptr_dst_addr->addr_bytes[2], ptr_dst_addr->addr_bytes[3],
					ptr_dst_addr->addr_bytes[4], ptr_dst_addr->addr_bytes[5]);
			rte_pktmbuf_free(buf);
		}
	}
}

/*
 * Process a batch of outgoing packets.
 */
static void dpdk_tx_burst(uint8_t port)
{
	struct rte_mbuf *bufs[PKT_BURST_SIZE];
	uint16_t i, j, n_pkts, nb_tx;
	struct proc *p;
	struct thread *t;
	uint64_t cmd;
	unsigned long payload;
	struct tx_net_hdr *net_hdr;
	int ret;
	struct rte_mbuf *buf;

	/* Poll each thread in each runtime until all have been polled or we have
	 * PKT_BURST_SIZE pkts. TODO: maintain state across calls to this function
	 * to avoid starving threads/runtimes with higher indices. */
	n_pkts = 0;
	for (i = 0; i < nr_clients; i++) {
		p = clients[i];
		for (j = 0; j < p->thread_count; j++) {
			t = &p->threads[j];
			if (lrpc_recv(&t->txpktq, &cmd, &payload)) {
				net_hdr = shmptr_to_ptr(&p->region, payload,
						sizeof(struct tx_net_hdr));

				ret = rte_mempool_get(egress_mbuf_pool, (void **) &buf);
				if (ret < 0) {
					/* TODO: send completion to free net_hdr's memory */
					log_warn("dpdk: error getting mbuf from mempool");
					goto done_polling;
				}

				dpdk_prepare_tx_mbuf(buf, net_hdr, p, t);

				bufs[n_pkts++] = buf;

				if (n_pkts >= PKT_BURST_SIZE)
					goto done_polling;
			}
		}
	}

	if (n_pkts == 0)
		return;

done_polling:
	/* send packets to NIC queue */
	nb_tx = rte_eth_tx_burst(port, 0, bufs, n_pkts);
	log_debug("dpdk: transmitted %d packets on port %d", nb_tx, port);

	if (nb_tx < n_pkts) {
		for (i = nb_tx; i < n_pkts; i++)
			rte_pktmbuf_free(bufs[i]);
	}
}

/*
 * Process a batch of commands from runtimes.
 */
static void dpdk_handle_runtime_commands()
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
	for (i = 0; i < nr_clients; i++) {
		p = clients[i];
		for (j = 0; j < p->thread_count; j++) {
			t = &p->threads[j];
			if (lrpc_recv(&t->txcmdq, &cmd, &payload)) {
				if (cmd == TXCMD_NET_COMPLETE) {
					/* get pointer to struct rte_mbuf, return to mempool */
					buf = (struct rte_mbuf *)payload;
					rte_pktmbuf_free(buf);
				} else
					log_err("dpdk: TXCMD %lu not handled", cmd);

				n_cmds++;
				if (n_cmds >= CMD_BURST_SIZE)
					return;
			}
		}
	}
}

/*
 * Add a new client.
 */
static inline void dpdk_add_client(struct proc *p)
{
	int ret;

	clients[nr_clients++] = p;

	ret = rte_hash_add_key_data(mac_to_proc, &p->mac.addr[0], p);
	if (ret < 0)
		log_err("dpdk: failed to add MAC to hash table in add_client");
}

/*
 * Remove a client. Notify control plane once removal is complete so that it
 * can delete its data structures.
 */
static inline void dpdk_remove_client(struct proc *p)
{
	int i, ret;

	for (i = 0; i < nr_clients; i++) {
		if (clients[i] == p)
			break;
	}

	if (i == nr_clients) {
		WARN();
		return;
	}

	clients[i] = clients[nr_clients - 1];
	nr_clients--;

	ret = rte_hash_del_key(mac_to_proc, &p->mac.addr[0]);
	if (ret < 0)
		log_err("dpdk: failed to remove MAC from hash table in remove client");

	/* TODO: free queued packets/commands? */

	if (!lrpc_send(&lrpc_data_to_control, CONTROL_PLANE_REMOVE_CLIENT,
			(unsigned long) p))
		log_err("dpdk: failed to inform control of client removal");
}

/*
 * Process a batch of messages from the control plane.
 */
static void dpdk_rx_control_lrpcs(void)
{
	uint64_t cmd;
	unsigned long payload;
	uint16_t n_rx = 0;
	struct proc *p;

	while (lrpc_recv(&lrpc_control_to_data, &cmd, &payload)
			&& n_rx < CONTROL_BURST_SIZE) {
		p = (struct proc *) payload;

		switch (cmd)
		{
		case DATAPLANE_ADD_CLIENT:
			dpdk_add_client(p);
			break;
		case DATAPLANE_REMOVE_CLIENT:
			dpdk_remove_client(p);
			break;
		default:
			log_err("dpdk: received unrecognized command %lu", cmd);
		}

		n_rx++;
	}
}

/*
 * The main thread. Reads packets from ingress queues, sends packets out egress
 * queues, and handles lrpcs from the control thread.
 */
void dpdk_loop(uint8_t port)
{
	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	if (rte_eth_dev_socket_id(port) > 0
			&& rte_eth_dev_socket_id(port) != (int) rte_socket_id())
		printf("WARNING, port %u is on remote NUMA node to polling thread.\n\t"
				"Performance will not be optimal.\n", port);

	printf("\nCore %u running dataplane. [Ctrl+C to quit]\n", rte_lcore_id());

	/* Run until the application is quit or killed. */
	for (;;) {
		/* handle a burst of ingress packets. */
		dpdk_rx_burst(port);

		/* send a burst of egress packets. */
		dpdk_tx_burst(port);

		/* process a batch of commands from runtimes */
		dpdk_handle_runtime_commands();

		/* handle control messages. */
		dpdk_rx_control_lrpcs();
	}
}

/*
 * Initialize channels for communicating with the I/O kernel control plane.
 */
static int dpdk_init_control_comm(void)
{
	int ret;

	ret = lrpc_init_in(&lrpc_control_to_data,
			lrpc_control_to_data_params.buffer, CONTROL_DATAPLANE_QUEUE_SIZE,
			lrpc_control_to_data_params.wb);
	if (ret < 0) {
		log_err("dpdk: initializing LRPC from control plane failed");
		return -1;
	}

	ret = lrpc_init_out(&lrpc_data_to_control,
			lrpc_data_to_control_params.buffer, CONTROL_DATAPLANE_QUEUE_SIZE,
			lrpc_data_to_control_params.wb);
	if (ret < 0) {
		log_err("dpdk: initializing LRPC to control plane failed");
		return -1;
	}

	return 0;
}

/*
 * Initialize dpdk.
 */
int dpdk_init(uint8_t port)
{
	struct rte_mempool *ingress_mbuf_pool;
	unsigned nb_ports;
	char *argv[] = { "./iokerneld", "-l", "2", "--socket-mem=128" };
	struct rte_hash_parameters hash_params = { 0 };

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(sizeof(argv) / sizeof(argv[0]), argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	/* Check that there is a port to send/receive on. */
	nb_ports = rte_eth_dev_count();
	if (nb_ports < 1)
		rte_exit(EXIT_FAILURE, "Error: no available ports\n");

	/* Create a new mempool in shared memory to hold the ingress mbufs. */
	ingress_mbuf_pool = dpdk_pktmbuf_pool_create_in_shm("INGRESS_MBUF_POOL",
			NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (ingress_mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create ingress mbuf pool\n");

	/* Initialize port. */
	if (dpdk_port_init(port, ingress_mbuf_pool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n", port);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Create a new dummy mempool to handle completions for egress packets. */
	egress_mbuf_pool = dpdk_pktmbuf_completion_pool_create("EGRESS_MBUF_POOL",
			NUM_MBUFS * nb_ports, sizeof(struct egress_pktmbuf_priv),
			rte_socket_id());

	if (egress_mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create egress mbuf pool\n");

	/* Initialize the hash table for mapping MACs to runtimes. */
	hash_params.name = "mac_to_proc_hash_table";
	hash_params.entries = MAC_TO_PROC_ENTRIES;
	hash_params.key_len = ETHER_ADDR_LEN;
	hash_params.hash_func = rte_jhash;
	hash_params.hash_func_init_val = 0;
	hash_params.socket_id = rte_socket_id();
	mac_to_proc = rte_hash_create(&hash_params);
	if (mac_to_proc == NULL)
		rte_exit(EXIT_FAILURE, "Failed to create MAC to proc hash table");

	if (dpdk_init_control_comm() < 0)
		rte_exit(EXIT_FAILURE,
				"Cannot initialize communication with control plane");

	return 0;
}
