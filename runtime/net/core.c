/*
 * core.c - core networking infrastructure
 */

#include <runtime/thread.h>

#include "../defs.h"
#include "defs.h"

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

int net_rx_register_handler(struct rx_handler *h)
{
	return -ENOSYS;
}

void net_rx_unregister_handler(struct rx_handler *h)
{

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

void __net_schedule(void)
{

} 
