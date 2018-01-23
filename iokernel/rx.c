/*
 * rx.c - the receive path for the I/O kernel (network -> runtimes)
 */

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include <base/log.h>
#include <iokernel/queue.h>
#include <iokernel/shm.h>

#include "defs.h"

#define MBUF_CACHE_SIZE 250

static struct shm_region ingress_mbuf_region;

/*
 * Prepend rx_net_hdr preamble to ingress packets.
 */
static struct rx_net_hdr *rx_prepend_rx_preamble(struct rte_mbuf *buf)
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
 * Send a packet up to a runtime. Return true if successful, false otherwise.
 */
static bool rx_enqueue_to_runtime(struct rx_net_hdr *net_hdr, struct proc *p)
{
	bool wake_kthread = false;
	int kthread, r, index;
	struct thread *t;
	shmptr_t shmptr;
	bool success;

	if (p->active_thread_count == 0) {
		/* reserve a kthread and core to use */
		wake_kthread = true;
		kthread = cores_reserve_core(p);
		if (kthread < 0) {
			log_err("rx: no available kthreads to handle rx packet");
			BUG(); /* not handled */
		}
	} else {
		/* choose a random thread from the active threads */
		r = rand() % p->active_thread_count;
		index = -1;
		bitmap_for_each_cleared(p->available_threads, p->thread_count,
				kthread) {
			if (++index == r)
				break;
		}
		BUG_ON(kthread == -1); /* didn't find an active kthread */
	}
	t = &p->threads[kthread];

	shmptr = ptr_to_shmptr(&ingress_mbuf_region, net_hdr,
			sizeof(struct rx_net_hdr));

	success = lrpc_send(&t->rxq, RX_NET_RECV, shmptr);

	/* enqueue the packet before we wake the kthread so there's no risk of it
	 * immediately parking again */
	if (wake_kthread)
		cores_wake_kthread(p, kthread);

	return success;
}

/*
 * Process a batch of incoming packets.
 */
void rx_burst()
{
	struct rte_mbuf *bufs[IOKERNEL_PKT_BURST_SIZE];
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
	nb_rx = rte_eth_rx_burst(dp.port, 0, bufs, IOKERNEL_PKT_BURST_SIZE);
	if (nb_rx > 0)
		log_debug("rx: received %d packets on port %d", nb_rx, dp.port);

	for (i = 0; i < nb_rx; i++) {
		/* parse dst ether addr */
		buf = bufs[i];

		ptr_mac_hdr = rte_pktmbuf_mtod(buf, struct ether_hdr *);
		ptr_dst_addr = &ptr_mac_hdr->d_addr;
		log_debug("rx: rx packet with MAC %02" PRIx8 " %02" PRIx8 " %02"
				PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8,
				ptr_dst_addr->addr_bytes[0], ptr_dst_addr->addr_bytes[1],
				ptr_dst_addr->addr_bytes[2], ptr_dst_addr->addr_bytes[3],
				ptr_dst_addr->addr_bytes[4], ptr_dst_addr->addr_bytes[5]);

		if (is_unicast_ether_addr(ptr_dst_addr)) {
			/* lookup runtime by MAC in hash table */
			ret = rte_hash_lookup_data(dp.mac_to_proc,
					&ptr_dst_addr->addr_bytes[0], &data);
			if (ret < 0) {
				log_warn("rx: received packet for unregistered MAC");
				rte_pktmbuf_free(buf);
				continue;
			}

			p = (struct proc *) data;
			net_hdr = rx_prepend_rx_preamble(buf);
			if (!rx_enqueue_to_runtime(net_hdr, p)) {
				log_warn("rx: failed to enqueue unicast packet to runtime");
				rte_pktmbuf_free(buf);
			}
		} else if (is_broadcast_ether_addr(ptr_dst_addr)
				&& dp.nr_clients > 0) {
			/* forward to all registered runtimes */
			net_hdr = rx_prepend_rx_preamble(buf);

			n_sent = 0;
			for (j = 0; j < dp.nr_clients; j++) {
				success = rx_enqueue_to_runtime(net_hdr, dp.clients[j]);
				if (success)
					n_sent++;
				else
					log_warn("rx: failed to enqueue broadcast packet to "
							"runtime");
			}

			if (n_sent == 0)
				rte_pktmbuf_free(buf);
			else
				rte_mbuf_refcnt_update(buf, n_sent - 1);
		} else {
			log_warn("rx: unhandled packet with MAC %x %x %x %x %x %x",
					ptr_dst_addr->addr_bytes[0], ptr_dst_addr->addr_bytes[1],
					ptr_dst_addr->addr_bytes[2], ptr_dst_addr->addr_bytes[3],
					ptr_dst_addr->addr_bytes[4], ptr_dst_addr->addr_bytes[5]);
			rte_pktmbuf_free(buf);
		}
	}
}

/*
 * Callback to unmap the shared memory used by a mempool when destroying it.
 */
static void rx_mempool_memchunk_free(struct rte_mempool_memhdr *memhdr,
		void *opaque)
{
	mem_unmap_shm(opaque);
}

/*
 * Create and initialize a packet mbuf pool in shared memory, based on
 * rte_pktmbuf_pool_create.
 */
static struct rte_mempool *rx_pktmbuf_pool_create_in_shm(const char *name,
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
		log_err("rx: mbuf priv_size=%u is not aligned", priv_size);
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
		log_err("rx: error setting mempool handler");
		goto fail_free_mempool;
	}
	rte_pktmbuf_pool_init(mp, &mbp_priv);

	/* check necessary size and map shared memory */
	total_elt_sz = mp->header_size + mp->elt_size + mp->trailer_size;
	pg_size = PGSIZE_2MB;
	pg_shift = rte_bsf32(pg_size);
	len = rte_mempool_xmem_size(n, total_elt_sz, pg_shift);
	if (len > INGRESS_MBUF_SHM_SIZE) {
		log_err("rx: shared memory is too small for number of mbufs");
		goto fail_free_mempool;
	}

	shbuf = mem_map_shm(INGRESS_MBUF_SHM_KEY, NULL, INGRESS_MBUF_SHM_SIZE,
			pg_size, true);
	if (shbuf == MAP_FAILED) {
		log_err("rx: mem_map_shm failed");
		goto fail_free_mempool;
	}
	ingress_mbuf_region.base = shbuf;
	ingress_mbuf_region.len = len;

	/* populate mempool using shared memory */
	ret = rte_mempool_populate_virt(mp, shbuf, len, pg_size,
			rx_mempool_memchunk_free, shbuf);
	if (ret < 0) {
		log_err("rx: error populating mempool %d", ret);
		goto fail_unmap_memory;
	}

	rte_mempool_obj_iter(mp, rte_pktmbuf_init, NULL);

	return mp;

fail_unmap_memory:
	mem_unmap_shm(shbuf);
fail_free_mempool:
	rte_mempool_free(mp);
fail:
	log_err("rx: couldn't create pktmbuf pool %s", name);
	return NULL;
}

/*
 * Initialize rx state.
 */
int rx_init()
{
	/* create a mempool in shared memory to hold the rx mbufs */
	dp.rx_mbuf_pool = rx_pktmbuf_pool_create_in_shm("RX_MBUF_POOL",
			IOKERNEL_NUM_MBUFS, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_socket_id());

	if (dp.rx_mbuf_pool == NULL) {
		log_err("rx: couldn't create rx mbuf pool");
		return -1;
	}

	return 0;
}
