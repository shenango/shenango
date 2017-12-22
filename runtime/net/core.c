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

/* the maximum number of packets to process per scheduler invocation */
#define MAX_BUDGET	512

#define TEMP_IP_ADDR 3232235781 // 192.168.1.5
#define TEMP_NETMASK 0xffffff00 // 255.255.255.0
#define TEMP_GATEWAY 0

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

	iphdr = mbuf_pull_hdr_or_null(m, *iphdr);
	if (unlikely(!iphdr))
		goto drop;

	/* The NIC has validated IP checksum for us. */

	/* must be IPv4, no IP options, no IP fragments */
	if (unlikely(iphdr->version != IPVERSION ||
		     iphdr->header_len != sizeof(*iphdr) / sizeof(uint32_t) ||
		     (iphdr->off & IP_MF) > 0))
		goto drop;

	len = ntoh16(iphdr->len) - sizeof(*iphdr);
	if (unlikely(mbuf_length(m) < len))
		goto drop;

	switch(iphdr->proto) {
	case IPPROTO_ICMP:
		net_rx_icmp(m, iphdr, len);
		return;

	case IPPROTO_UDP:
		net_rx_udp_usocket(m, iphdr, len);
		return;

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
			recv_reqs[recv_cnt] = shmptr_to_ptr(&netcfg.rx_region,
				(shmptr_t)payload, MBUF_DEFAULT_LEN);
			BUG_ON(recv_reqs[recv_cnt] == NULL);
			recv_cnt++;
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
 * @type: the ethernet type
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
	if ((daddr & netcfg.netmask) != netcfg.network)
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

void net_schedule(struct kthread *k, unsigned int budget)
{
	net_rx_schedule(k, budget);
}

/**
 * net_init_thread - initializes per-thread state for the network stack
 *
 * Returns 0 (can't fail).
 */
int net_init_thread(void)
{
	int ret;

	tcache_init_perthread(net_mbuf_tcache, &net_mbuf_pt);
	tcache_init_perthread(net_tx_buf_tcache, &net_tx_buf_pt);

	ret = usocket_init_thread();
	if (ret)
		return ret;

	return 0;
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

	netcfg.addr = TEMP_IP_ADDR;
	netcfg.netmask = TEMP_NETMASK;
	netcfg.gateway = TEMP_GATEWAY;
	netcfg.network = netcfg.addr & netcfg.netmask;
	netcfg.broadcast = netcfg.network | ~netcfg.netmask;

	BUILD_ASSERT(sizeof(struct net_cfg) == CACHE_LINE_SIZE);

	ret = net_arp_init();
	if (ret)
		return ret;

	ret = usocket_init();
	if (ret)
		return ret;

	return 0;
}
