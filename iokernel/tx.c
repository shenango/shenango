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

#define TX_PREFETCH_STRIDE 2

static struct rte_mempool *tx_mbuf_pool;

/*
 * Private data stored in egress mbufs, used to send completions to runtimes.
 */
struct tx_pktmbuf_priv {
	struct proc	*p;
	struct thread	*th;
	unsigned long	completion_data;
};

static inline struct tx_pktmbuf_priv *tx_pktmbuf_get_priv(struct rte_mbuf *buf)
{
	return (struct tx_pktmbuf_priv *)(((char *)buf)
			+ sizeof(struct rte_mbuf));
}

/*
 * Prepare rte_mbuf struct for transmission.
 */
static void tx_prepare_tx_mbuf(struct rte_mbuf *buf,
			       const struct tx_net_hdr *net_hdr,
			       struct thread *th)
{
	struct proc *p = th->p;
	uint32_t page_number;
	struct tx_pktmbuf_priv *priv_data;

	/* initialize mbuf to point to net_hdr->payload */
	buf->buf_addr = (char *)net_hdr->payload;
	page_number = PGN_2MB((uintptr_t)buf->buf_addr - (uintptr_t)p->region.base);
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

		buf->l3_len = sizeof(struct ipv4_hdr);
		buf->l2_len = ETHER_HDR_LEN;
	}

	/* initialize the private data, used to send completion events */
	priv_data = tx_pktmbuf_get_priv(buf);
	priv_data->p = p;
	priv_data->th = th;
	priv_data->completion_data = net_hdr->completion_data;

	/* reference count @p so it doesn't get freed before the completion */
	proc_get(p);
}

/*
 * Send a completion event to the runtime for the mbuf pointed to by obj.
 */
bool tx_send_completion(void *obj)
{
	struct rte_mbuf *buf;
	struct tx_pktmbuf_priv *priv_data;
	struct thread *th;
	struct proc *p;

	buf = (struct rte_mbuf *)obj;
	priv_data = tx_pktmbuf_get_priv(buf);
	p = priv_data->p;

	/* during initialization, the mbufs are enqueued for the first time */
	if (unlikely(!p))
		return true;

	/* check if runtime is still registered */
	if(unlikely(p->kill)) {
		proc_put(p);
		return true; /* no need to send a completion */
	}

	/* send completion to runtime */
	th = priv_data->th;
	if (!th->parked) {
		if (!lrpc_send(&th->rxq, RX_NET_COMPLETE,
			       priv_data->completion_data)) {
			log_warn("tx: failed to send completion to runtime");
			return false;
		}
	} else {
		if (!rx_send_to_runtime(p, priv_data->th->tid, RX_NET_COMPLETE,
					priv_data->completion_data)) {
			log_warn("tx: failed to send completion to runtime");
			return false;
		}
	}

	proc_put(p);
	return true;
}

static int tx_drain_queue(struct thread *t, int n,
			  const struct tx_net_hdr **hdrs)
{
	int i;

	for (i = 0; i < n; i++) {
		uint64_t cmd;
		unsigned long payload;

		if (!lrpc_recv(&t->txpktq, &cmd, &payload)) {
			if (unlikely(t->parked))
				unpoll_thread(t);
			break;
		}

		/* TODO: need to kill the process? */
		BUG_ON(cmd != TXPKT_NET_XMIT);

		hdrs[i] = shmptr_to_ptr(&t->p->region, payload,
					sizeof(struct tx_net_hdr));
		/* TODO: need to kill the process? */
		BUG_ON(!hdrs[i]);
	}

	return i;
}


/*
 * Process a batch of outgoing packets.
 */
bool tx_burst(void)
{
	const struct tx_net_hdr *hdrs[IOKERNEL_TX_BURST_SIZE];
	struct rte_mbuf *bufs[IOKERNEL_TX_BURST_SIZE];
	struct thread *threads[IOKERNEL_TX_BURST_SIZE];
	int i, j, ret;
	static unsigned int pos = 0, n_pkts = 0, n_bufs = 0;

	/*
	 * Poll each kthread in each runtime until all have been polled or we
	 * have PKT_BURST_SIZE pkts.
	 */
	for (i = 0; i < nrts; i++) {
		unsigned int idx = (pos + i) % nrts;

		if (n_pkts >= IOKERNEL_TX_BURST_SIZE)
			goto full;
		ret = tx_drain_queue(ts[idx], IOKERNEL_TX_BURST_SIZE - n_pkts,
				     &hdrs[n_pkts]);
		for (j = n_pkts; j < n_pkts + ret; j++)
			threads[j] = ts[idx];
		n_pkts += ret;
	}

	if (n_pkts == 0)
		return false;

	pos++;

full:
	/* allocate mbufs */
	ret = rte_mempool_get_bulk(tx_mbuf_pool, (void **)&bufs[n_bufs],
				   n_pkts - n_bufs);
	if (unlikely(ret)) {
		log_warn("tx: error getting mbuf from mempool");
		return true;
	}

	/* fill in packet metadata */
	for (i = n_bufs; i < n_pkts; i++) {
		if (i + TX_PREFETCH_STRIDE < n_pkts)
			prefetch(hdrs[i + TX_PREFETCH_STRIDE]);
		tx_prepare_tx_mbuf(bufs[i], hdrs[i], threads[i]);
	}

	n_bufs = n_pkts;

	/* finally, send the packets on the wire */
	ret = rte_eth_tx_burst(dp.port, 0, bufs, n_pkts);
	log_debug("tx: transmitted %d packets on port %d", ret, dp.port);

	/* apply back pressure if the NIC TX ring was full */
	if (unlikely(ret < n_pkts)) {
		n_pkts -= ret;
		for (i = 0; i < n_pkts; i++) {
			bufs[i] = bufs[ret + i];
			threads[i] = threads[ret + i];
		}
	} else {
		n_pkts = 0;
	}

	n_bufs = n_pkts;
	return true;
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
