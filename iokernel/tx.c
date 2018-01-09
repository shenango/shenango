/*
 * tx.c - the transmission path for the I/O kernel (runtimes -> network)
 */

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#include <base/log.h>
#include <iokernel/queue.h>

#include "defs.h"

struct rte_mempool *tx_mbuf_pool;

/*
 * Private data stored in egress mbufs, used to send completions to runtimes.
 */
struct tx_pktmbuf_priv {
	pid_t			pid;
	struct thread	*thread;
	unsigned long	completion_data;
};

static inline struct tx_pktmbuf_priv *tx_pktmbuf_get_priv(struct rte_mbuf *buf)
{
	return (struct tx_pktmbuf_priv *) (((char *) buf)
			+ sizeof(struct rte_mbuf));
}

/*
 * Prepare rte_mbuf struct for transmission.
 */
static void tx_prepare_tx_mbuf(struct rte_mbuf *buf, struct tx_net_hdr *net_hdr,
		struct proc *p, struct thread *thread)
{
	uint32_t page_number;
	struct tx_pktmbuf_priv *priv_data;

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
	priv_data = tx_pktmbuf_get_priv(buf);
	priv_data->pid = p->pid;
	priv_data->thread = thread;
	priv_data->completion_data = net_hdr->completion_data;
}

/*
 * Send a completion event to the runtime for the mbuf pointed to by obj.
 */
bool tx_send_completion(void *obj) {
	struct rte_mbuf *buf;
	struct tx_pktmbuf_priv *priv_data;
	int ret;
	void *data;
	struct thread *t;

	if (unlikely(dp.nr_clients == 0))
		return true;

	/* check if runtime is still registered */
	buf = (struct rte_mbuf *) obj;
	priv_data = tx_pktmbuf_get_priv(buf);
	ret = rte_hash_lookup_data(dp.pid_to_proc, &priv_data->pid, &data);
	if (ret < 0) {
		log_debug("tx: received completion for unregistered pid %u",
				priv_data->pid);
		return true; /* no need to send a completion */
	}

	/* send completion to runtime */
	t = priv_data->thread;
	if (!lrpc_send(&t->rxq, RX_NET_COMPLETE, priv_data->completion_data)) {
		log_warn("tx: failed to enqueue completion event to runtime");
		return false;
	}

	return true;
}

/*
 * Process a batch of outgoing packets.
 */
void tx_burst()
{
	struct rte_mbuf *bufs[IOKERNEL_PKT_BURST_SIZE];
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
	for (i = 0; i < dp.nr_clients; i++) {
		p = dp.clients[i];
		for (j = 0; j < p->thread_count; j++) {
			t = &p->threads[j];
			if (lrpc_recv(&t->txpktq, &cmd, &payload)) {
				net_hdr = shmptr_to_ptr(&p->region, payload,
						sizeof(struct tx_net_hdr));

				ret = rte_mempool_get(tx_mbuf_pool, (void **) &buf);
				if (ret < 0) {
					/* TODO: send completion to free net_hdr's memory */
					log_warn("tx: error getting mbuf from mempool");
					goto done_polling;
				}

				tx_prepare_tx_mbuf(buf, net_hdr, p, t);

				bufs[n_pkts++] = buf;

				if (n_pkts >= IOKERNEL_PKT_BURST_SIZE)
					goto done_polling;
			}
		}
	}

	if (n_pkts == 0)
		return;

done_polling:
	/* send packets to NIC queue */
	nb_tx = rte_eth_tx_burst(dp.port, 0, bufs, n_pkts);
	log_debug("tx: transmitted %d packets on port %d", nb_tx, dp.port);

	if (nb_tx < n_pkts) {
		for (i = nb_tx; i < n_pkts; i++)
			rte_pktmbuf_free(bufs[i]);
	}
}

/*
 * Create and initialize a packet mbuf pool for holding struct mbufs and
 * handling completion events. Actual buffer memory is separate, in shared
 * memory.
 */
static struct rte_mempool *tx_pktmbuf_completion_pool_create(const char *name,
		unsigned n, uint16_t priv_size, int socket_id)
{
	struct rte_mempool *mp;
	struct rte_pktmbuf_pool_private mbp_priv;
	unsigned elt_size;
	int ret;

	if (RTE_ALIGN(priv_size, RTE_MBUF_PRIV_ALIGN) != priv_size) {
		log_err("tx: mbuf priv_size=%u is not aligned", priv_size);
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
		log_err("tx: error setting mempool handler");
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
 * Initialize tx state.
 */
int tx_init()
{
	/* create a mempool to hold struct rte_mbufs and handle completions */
	tx_mbuf_pool = tx_pktmbuf_completion_pool_create("TX_MBUF_POOL",
			IOKERNEL_NUM_MBUFS, sizeof(struct tx_pktmbuf_priv),
			rte_socket_id());

	if (tx_mbuf_pool == NULL) {
		log_err("tx: couldn't create tx mbuf pool");
		return -1;
	}

	return 0;
}
