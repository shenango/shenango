/*
 * core.c - core networking infrastructure
 */

#include <base/log.h>
#include <base/mempool.h>
#include <base/slab.h>
#include <base/hash.h>
#include <runtime/thread.h>

#include "defs.h"

#define IP_ID_SEED	0x42345323
#define RX_PREFETCH_STRIDE 2

/* the maximum number of packets to process per scheduler invocation */
#define MAX_BUDGET	512

/* important global state */
struct net_cfg netcfg __aligned(CACHE_LINE_SIZE);

/* mbuf allocation */
static struct slab net_mbuf_slab;
static struct tcache *net_mbuf_tcache;
static __thread struct tcache_perthread net_mbuf_pt;

/* TX buffer allocation */
static struct mempool net_tx_buf_mp;
static struct tcache *net_tx_buf_tcache;
static __thread struct tcache_perthread net_tx_buf_pt;

/* drains overflow queues */
void __noinline __net_recurrent(void)
{
	shmptr_t shm;
	struct mbuf *m;
	struct rx_net_hdr *rxhdr;
	struct kthread *k = myk();

	/* drain TX packets */
	while (!mbufq_empty(&k->txpktq_overflow)) {
		m = mbufq_peak_head(&k->txpktq_overflow);
		shm = ptr_to_shmptr(&netcfg.tx_region,
				    mbuf_data(m), mbuf_length(m));
		if (!lrpc_send(&k->txpktq, TXPKT_NET_XMIT, shm))
			break;
		mbufq_pop_head(&k->txpktq_overflow);
	}

	/* drain RX completions */
	while (!mbufq_empty(&k->txcmdq_overflow)) {
		m = mbufq_peak_head(&k->txcmdq_overflow);
		rxhdr = container_of((void *)m->head, struct rx_net_hdr,
				     payload);
		if (!lrpc_send(&k->txcmdq, TXCMD_NET_COMPLETE,
			       rxhdr->completion_data))
			break;
		mbufq_pop_head(&k->txcmdq_overflow);
		tcache_free(&net_mbuf_pt, m);
	}
}


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
	m->len = hdr->len;
	m->csum_type = hdr->csum_type;
	m->csum = hdr->csum;
	m->rss_hash = hdr->rss_hash;
	m->release_data = 0;
	m->release = net_rx_release_mbuf;
	return m;
}

static inline bool ip_hdr_supported(const struct ip_hdr *iphdr)
{
	/* must be IPv4, no IP options, no IP fragments */
	return (iphdr->version == IPVERSION &&
		iphdr->header_len == sizeof(*iphdr) / sizeof(uint32_t) &&
		(iphdr->off & IP_MF) == 0);
}

/**
 * net_error - reports a network error so that it can be passed to higher layers
 * @m: the egress mbuf that triggered the error
 * @err: the suggested error code to report
 *
 * The mbuf data pointer must point to the network-layer (L3) hdr that failed.
 */
void net_error(struct mbuf *m, int err)
{
	const struct ip_hdr *iphdr;

	iphdr = mbuf_pull_hdr_or_null(m, *iphdr);
	if (unlikely(!iphdr))
		return;
	if (unlikely(!ip_hdr_supported(iphdr)))
		return;

	/* don't check length because ICMP may not provide the full payload */

	/* so far we only support error handling in UDP */
	if (iphdr->proto == IPPROTO_UDP)
		udp_error(m, iphdr, err);
}

static void net_rx_one(struct rx_net_hdr *hdr)
{
	struct mbuf *m;
	const struct eth_hdr *llhdr;
	const struct ip_hdr *iphdr;
	uint16_t len;

	m = net_rx_alloc_mbuf(hdr);
	if (unlikely(!m)) {
		while (!lrpc_send(&myk()->txcmdq, TXCMD_NET_COMPLETE,
				  hdr->completion_data)) {
			cpu_relax();
		}
		return;
	}

	STAT(RX_PACKETS)++;
	STAT(RX_BYTES) += mbuf_length(m);

	/* Did HW checksum verification pass? */
	if (hdr->csum_type != CHECKSUM_TYPE_UNNECESSARY)
		goto drop;


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
	BUILD_ASSERT(sizeof(llhdr->dhost.addr) == sizeof(netcfg.mac.addr));
	if (unlikely(ntoh16(llhdr->type) != ETHTYPE_IP ||
		     memcmp(llhdr->dhost.addr, netcfg.mac.addr,
			    sizeof(llhdr->dhost.addr)) != 0))
		goto drop;


	/*
	 * Network Layer Processing (OSI L3)
	 */

	mbuf_mark_network_offset(m);
	iphdr = mbuf_pull_hdr_or_null(m, *iphdr);
	if (unlikely(!iphdr))
		goto drop;

	/* The NIC has validated IP checksum for us. */

	if (unlikely(!ip_hdr_supported(iphdr)))
		goto drop;

	len = ntoh16(iphdr->len) - sizeof(*iphdr);
	if (unlikely(mbuf_length(m) < len))
		goto drop;

	switch(iphdr->proto) {
	case IPPROTO_ICMP:
		net_rx_icmp(m, iphdr, len);
		return;

	case IPPROTO_UDP:
		net_rx_udp(m, iphdr, len);
		return;

	default:
		goto drop;
	}

	return;

drop:
	mbuf_drop(m);
}

struct net_rx_closure {
	unsigned int recv_cnt, compl_cnt;
	struct rx_net_hdr *recv_reqs[MAX_BUDGET];
	struct mbuf *compl_reqs[MAX_BUDGET];
	bool kthread_parked;
	struct kthread *k;
};

static void net_rx_worker(void *arg)
{
	struct net_rx_closure *c = arg;
	int i;

	/* complete TX requests and free packets */
	for (i = 0; i < c->compl_cnt; i++)
		mbuf_free(c->compl_reqs[i]);

	/* deliver new RX packets to the runtime */
	for (i = 0; i < c->recv_cnt; i++) {
		if (i + RX_PREFETCH_STRIDE < c->recv_cnt)
			prefetch(c->recv_reqs[i + RX_PREFETCH_STRIDE]);
		net_rx_one(c->recv_reqs[i]);
	}

	/* detach kthread if iokernel has parked it */
	if (c->kthread_parked) {
		spin_lock(&c->k->lock);
		kthread_detach(c->k);
		spin_unlock(&c->k->lock);
	}
}

/**
 * net_run - creates a closure for network receive processing
 * @k: the kthread from which to take RX queue commands
 * @budget: the maximum number of commands to process
 *
 * Returns a thread that handles receive processing when executed or
 * NULL if no receive processing work is available.
 */
thread_t *net_run(struct kthread *k, unsigned int budget)
{
	thread_t *th;
	struct net_rx_closure *c;
	unsigned int recv_cnt = 0, compl_cnt = 0;
	int budget_left;

	assert_spin_lock_held(&k->lock);

	if (lrpc_empty(&k->rxq))
		return NULL;

	th = thread_create_with_buf(net_rx_worker, (void **)&c, sizeof(*c));
	if (unlikely(!th))
		return NULL;

	c->kthread_parked = false;
	c->k = k;
	budget_left = min(budget, MAX_BUDGET);
	while (budget_left--) {
		uint64_t cmd;
		unsigned long payload;

		if (!lrpc_recv(&k->rxq, &cmd, &payload))
			break;

		switch (cmd) {
		case RX_NET_RECV:
			c->recv_reqs[recv_cnt] = shmptr_to_ptr(&netcfg.rx_region,
				(shmptr_t)payload, MBUF_DEFAULT_LEN);
			BUG_ON(c->recv_reqs[recv_cnt] == NULL);
			recv_cnt++;
			break;

		case RX_NET_COMPLETE:
			c->compl_reqs[compl_cnt++] = (struct mbuf *)payload;
			break;

		case RX_NET_PARKED:
			c->kthread_parked = true;
			break;

		default:
			log_err_ratelimited("net: invalid RXQ cmd '%ld'", cmd);
		}
	}

	assert(recv_cnt + compl_cnt > 0 || c->kthread_parked);
	c->recv_cnt = recv_cnt;
	c->compl_cnt = compl_cnt;
	th->state = THREAD_STATE_RUNNABLE;
	return th;
}


/*
 * TX Networking Functions
 */

/**
 * net_tx_release_mbuf - the default TX mbuf release handler
 * @m: the mbuf to free
 *
 * Normally, this handler will get called automatically. If you override
 * mbuf.release(), call this method manually.
 */
void net_tx_release_mbuf(struct mbuf *m)
{
	tcache_free(&net_tx_buf_pt, m->head);
	tcache_free(&net_mbuf_pt, m);
}

/**
 * net_tx_alloc_mbuf - allocates an mbuf for transmitting.
 *
 * Returns an mbuf, or NULL if out of memory.
 */
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

static void net_tx_raw(struct mbuf *m)
{
	shmptr_t shm;
	struct tx_net_hdr *hdr;
	unsigned int len = mbuf_length(m);

	/* drain pending overflow packets first */
	net_recurrent();

	STAT(TX_PACKETS)++;
	STAT(TX_BYTES) += len;

	hdr = mbuf_push_hdr(m, *hdr);
	hdr->completion_data = (unsigned long)m;
	hdr->len = len;
	hdr->olflags = m->txflags;

	shm = ptr_to_shmptr(&netcfg.tx_region, hdr, len + sizeof(*hdr));
	if (!lrpc_send(&myk()->txpktq, TXPKT_NET_XMIT, shm))
		mbufq_push_tail(&myk()->txpktq_overflow, m);
}

/**
 * net_tx_eth - transmits an ethernet packet
 * @m: the mbuf to transmit
 * @type: the ethernet type (in native byte order)
 * @dhost: the destination MAC address
 *
 * The payload must start with the network (L3) header. The ethernet (L2)
 * header will be prepended by this function.
 *
 * @m must have been allocated with net_tx_alloc_mbuf().
 *
 * Returns 0 if successful. If successful, the mbuf will be freed when the
 * transmit completes. Otherwise, the mbuf still belongs to the caller.
 */
int net_tx_eth(struct mbuf *m, uint16_t type, struct eth_addr dhost)
{
	struct eth_hdr *eth_hdr;

	eth_hdr = mbuf_push_hdr(m, *eth_hdr);
	eth_hdr->shost = netcfg.mac;
	eth_hdr->dhost = dhost;
	eth_hdr->type = hton16(type);
	net_tx_raw(m);
	return 0;
}

/**
 * net_tx_ip - transmits an IP packet
 * @m: the mbuf to transmit
 * @proto: the transport protocol
 * @daddr: the destination IP address (in native byte order)
 *
 * The payload must start with the transport (L4) header. The IPv4 (L3) and
 * ethernet (L2) headers will be prepended by this function.
 *
 * @m must have been allocated with net_tx_alloc_mbuf().
 *
 * TODO: Support "don't fragment" (DF) flag?
 *
 * Returns 0 if successful. If successful, the mbuf will be freed when the
 * transmit completes. Otherwise, the mbuf still belongs to the caller.
 */
int net_tx_ip(struct mbuf *m, uint8_t proto, uint32_t daddr)
{
	struct eth_addr dhost;
	struct ip_hdr *iphdr;
	int ret;

	/* populate IP header */
	iphdr = mbuf_push_hdr(m, *iphdr);
	iphdr->version = IPVERSION;
	iphdr->header_len = 5;
	iphdr->tos = IPTOS_DSCP_CS0 | IPTOS_ECN_NOTECT;
	iphdr->len = hton16(mbuf_length(m));
	/* This must be unique across datagrams within a flow, see RFC 6864 */
	iphdr->id = hash_crc32c_two(IP_ID_SEED, rdtsc() ^ proto,
				    (uint64_t)daddr |
				    ((uint64_t)netcfg.addr << 32));
	iphdr->off = 0;
	iphdr->ttl = 64;
	iphdr->proto = proto;
	iphdr->chksum = 0;
	iphdr->saddr = hton32(netcfg.addr);
	iphdr->daddr = hton32(daddr);

	/* ask NIC to calculate IP checksum */
	m->txflags |= OLFLAG_IP_CHKSUM | OLFLAG_IPV4;

	/* simple IP routing */
	if ((daddr & netcfg.netmask) != (netcfg.addr & netcfg.netmask))
		daddr = netcfg.gateway;

	/* need to use ARP to resolve dhost */
	ret = arp_lookup(daddr, &dhost, m);
	if (unlikely(ret)) {
		if (ret == -EINPROGRESS) {
			/* ARP code now owns the mbuf */
			return 0;
		} else {
			/* An unrecoverable error occurred */
			mbuf_pull_hdr(m, *iphdr);
			return ret;
		}
	}

	ret = net_tx_eth(m, ETHTYPE_IP, dhost);
	assert(!ret); /* can't fail as implemented so far */
	return 0;
}

/**
 * net_init_thread - initializes per-thread state for the network stack
 *
 * Returns 0 (can't fail).
 */
int net_init_thread(void)
{
	tcache_init_perthread(net_mbuf_tcache, &net_mbuf_pt);
	tcache_init_perthread(net_tx_buf_tcache, &net_tx_buf_pt);
	return 0;
}


static void net_dump_config(void)
{
	char buf[IP_ADDR_STR_LEN];

	log_info("net: using the following configuration:");
	log_info("  addr:\t%s", ip_addr_to_str(netcfg.addr, buf));
	log_info("  netmask:\t%s", ip_addr_to_str(netcfg.netmask, buf));
	log_info("  gateway:\t%s", ip_addr_to_str(netcfg.gateway, buf));
	log_info("  mac:\t%02X:%02X:%02X:%02X:%02X:%02X",
		 netcfg.mac.addr[0], netcfg.mac.addr[1], netcfg.mac.addr[2],
		 netcfg.mac.addr[3], netcfg.mac.addr[4], netcfg.mac.addr[5]);
}

/**
 * net_init - initializes the network stack
 *
 * Returns 0 if successful.
 */
int net_init(void)
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

	ret = mempool_create(&net_tx_buf_mp, iok.tx_buf, iok.tx_len,
			     PGSIZE_2MB, MBUF_DEFAULT_LEN);
	if (ret)
		return ret;

	net_tx_buf_tcache = mempool_create_tcache(&net_tx_buf_mp,
		"runtime_tx_bufs", TCACHE_DEFAULT_MAG_SIZE);
	if (!net_tx_buf_tcache)
		return -ENOMEM;

	log_info("net: started network stack");
	net_dump_config();
	return 0;
}
