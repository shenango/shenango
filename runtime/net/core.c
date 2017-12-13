/*
 * core.c - core networking infrastructure
 */

#include <base/log.h>
#include <base/mempool.h>
#include <base/slab.h>
#include <runtime/thread.h>

#include "../defs.h"
#include "defs.h"

/* the maximum number of packets to process per scheduler invocation */
#define MAX_BUDGET	512

/* important global state */
struct eth_addr net_local_mac;
struct ip_addr net_local_ip;

/* mbuf allocation */
static struct slab net_mbuf_slab;
static struct tcache *net_mbuf_tcache;
static __thread struct tcache_perthread net_mbuf_pt;

/* TX buffer allocation */
static struct mempool net_tx_buf_mp;
static struct tcache *net_tx_buf_tcache;
static __thread struct tcache_perthread net_tx_buf_pt;

/* RX shared memory region */
static struct shm_region net_rx_region;


/*
 * RX Networking Functions
 */

static void net_rx_release_mbuf(struct mbuf *m)
{
	struct rx_net_hdr *hdr = container_of((void *)m->head,
					      struct rx_net_hdr, payload);

	if (!lrpc_send(&myk()->txcmdq, TXCMD_NET_COMPLETE,
		       hdr->completion_data)) {
		mbufq_push_tail(&myk()->txcmdq_overflow, m);
		return;
	}
	tcache_free(&net_mbuf_pt, m);
}

static struct mbuf *net_rx_alloc_mbuf(struct rx_net_hdr *hdr)
{
	struct mbuf *m;

	m = tcache_alloc(&net_mbuf_pt);
	if (unlikely(!m))
		return NULL;

	mbuf_init(m, (unsigned char *)hdr->payload, hdr->len, 0);
	m->csum_type = hdr->csum_type;
	m->csum = hdr->csum;
	m->rss_hash = hdr->rss_hash;
	m->release_data = 0;
	m->release = net_rx_release_mbuf;
	return m;
}

static void net_rx_one(struct rx_net_hdr *hdr)
{
	struct mbuf *m;
	struct eth_hdr *llhdr;
	struct ip_hdr *iphdr;
	uint16_t len;

	m = net_rx_alloc_mbuf(hdr);
	if (unlikely(!m)) {
		while (!lrpc_send(&myk()->txcmdq, TXCMD_NET_COMPLETE,
				  hdr->completion_data)) {
			cpu_relax();
		}
		return;
	}


	/*
	 * Link Layer Processing (OSI L2)
	 */

	llhdr = mbuf_pull_hdr_or_null(m, *llhdr);
	if (unlikely(!llhdr))
		goto drop;

	/* handle ARP requests */
	if (ntoh16(llhdr->type) == ETHTYPE_ARP) {
		net_rx_arp(m);
		return;
	}

	/* filter out requests we can't handle */
	if (unlikely(ntoh16(llhdr->type) != ETHTYPE_IP ||
		     llhdr->dhost.addr != net_local_mac.addr))
		goto drop;


	/*
	 * Network Layer Processing (OSI L3)
	 */

	iphdr = mbuf_pull_hdr_or_null(m, *iphdr);
	if (unlikely(!iphdr))
		goto drop;

	/* TODO: Has the NIC validated IP checksum for us? */

	/* must be IPv4, no IP options, no IP fragments */
	if (unlikely(iphdr->version != IPVERSION ||
		     iphdr->header_len != sizeof(*iphdr) / sizeof(uint32_t) ||
		     (iphdr->off & IP_MF) > 0))
		goto drop;

	len = ntoh16(iphdr->len);

	switch(iphdr->proto) {
	case IPPROTO_ICMP:
		net_rx_icmp(m, &iphdr->src_addr, len);
		break;

	case IPPROTO_UDP:
		net_rx_udp(m, &iphdr->src_addr, len);
		break;

	default:
		goto drop;
	}

	return;

drop:
	mbuf_free(m);
}

static void net_rx_schedule(struct kthread *k, unsigned int budget)
{
	struct rx_net_hdr *recv_reqs[MAX_BUDGET];
	struct mbuf *completion_reqs[MAX_BUDGET];
	int recv_cnt = 0, completion_cnt = 0;
	int i;

	/* Step 1: Pull available IOKERNEL commands from the RXQ */
	budget = min(budget, MAX_BUDGET);
	while (budget--) {
		uint64_t cmd;
		unsigned long payload;

		if (!lrpc_recv(&k->rxq, &cmd, &payload))
			break;

		switch (cmd) {
		case RX_NET_RECV:
			recv_reqs[recv_cnt++] = shmptr_to_ptr(&net_rx_region,
				(shmptr_t)payload, MBUF_DEFAULT_LEN);
			BUG_ON(recv_reqs[recv_cnt - 1] == NULL);
			break;

		case RX_NET_COMPLETE:
			completion_reqs[completion_cnt++] =
				(struct mbuf *)payload;
			break;

		default:
			log_err_ratelimited("net: invalid RXQ cmd '%ld'", cmd);
		}
	}

	/* Step 2: Complete TX requests and free packets */
	for (i = 0; i < completion_cnt; i++)
		mbuf_free(completion_reqs[i]);

	/* Step 3: Deliver new RX packets to the runtime */
	for (i = 0; i < recv_cnt; i++)
		net_rx_one(recv_reqs[i]);
}


/*
 * TX Networking Functions
 */

void net_tx_release_mbuf(struct mbuf *m)
{
	tcache_free(&net_tx_buf_pt, m->head);
	tcache_free(&net_mbuf_pt, m);
}

struct mbuf *net_tx_alloc_mbuf(void)
{
	struct mbuf *m;
	unsigned char *buf;

	m = tcache_alloc(&net_mbuf_pt);
	if (unlikely(!m))
		return NULL;

	buf = tcache_alloc(&net_tx_buf_pt);
	if (unlikely(!buf)) {
		tcache_free(&net_mbuf_pt, m);
		return NULL;
	}

	mbuf_init(m, buf, MBUF_DEFAULT_LEN, MBUF_DEFAULT_HEADROOM);
	m->csum_type = CHECKSUM_TYPE_NEEDED;
	m->txflags = 0;
	m->release_data = 0;
	m->release = net_tx_release_mbuf;
	return m;
}

int net_tx_xmit(struct mbuf *m)
{
	return -ENOSYS;
}

void net_schedule(struct kthread *k, unsigned int budget)
{
	net_rx_schedule(k, budget);
}

int net_init_thread(void)
{
	tcache_init_perthread(net_mbuf_tcache, &net_mbuf_pt);
	tcache_init_perthread(net_tx_buf_tcache, &net_tx_buf_pt);
	return 0;
}

/**
 * net_init - initializes the network stack
 * @cfg: configuration parameters for initialization
 *
 * Returns 0 if successful.
 */
int net_init(struct net_cfg *cfg)
{
	int ret;

	ret = slab_create(&net_mbuf_slab, "runtime_mbufs",
			  sizeof(struct mbuf), 0);
	if (ret)
		return ret;

	net_mbuf_tcache = slab_create_tcache(&net_mbuf_slab,
					     TCACHE_DEFAULT_MAG_SIZE);
	if (!net_mbuf_tcache)
		return -ENOMEM;

	ret = mempool_create(&net_tx_buf_mp, cfg->tx_buf, cfg->tx_len,
			     PGSIZE_2MB, MBUF_DEFAULT_LEN);
	if (ret)
		return ret;

	net_tx_buf_tcache = mempool_create_tcache(&net_tx_buf_mp,
		"runtime_tx_bufs", TCACHE_DEFAULT_MAG_SIZE);
	if (!net_tx_buf_tcache)
		return -ENOMEM;

	net_local_mac = cfg->local_mac;
	net_local_ip = cfg->local_ip;
	net_rx_region = cfg->rx_region;

	return 0;
}
