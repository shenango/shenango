/*
 * udp.c - support for User Datagram Protocol (UDP)
 */

#include "defs.h"

#include <base/hash.h>
#include <base/log.h>
#include <base/smalloc.h>
#include <base/slab.h>
#include <base/tcache.h>
#include <net/udp.h>
#include <runtime/chan.h>
#include <runtime/rculist.h>
#include <runtime/net/usocket.h>

#include <string.h>

/** UDP socket stuff **/
#define NUSOCKET		512
#define PKT_QUEUE_CAPACITY		128
#define USOCKET_TABLE_CAPACITY		1024
#define UDP_SEED		0xDEADBEEF

#define UDP_HDR_SZ                                                             \
	(sizeof(struct eth_hdr) + sizeof(struct ip_hdr) +                      \
	 sizeof(struct udp_hdr))

#define MAX_UDP_PAYLOAD (ETH_MAX_LEN - UDP_HDR_SZ)

enum { STATE_INIT = 0,
       STATE_BOUND_QUEUE,
       STATE_BOUND_CALLBACK,
};

struct msg {
	struct mbuf *m;
	struct usocket *usock;
	struct addr raddr;
};

struct usocket {
	int descriptor;
	unsigned int state;
	struct rcu_hlist_node link;
	handler_fn_t handler;
	chan_t *pktq;
	struct addr laddr;
	struct addr raddr;
};

static DEFINE_SPINLOCK(usocket_lock);
static struct usocket *usockets[NUSOCKET];
static struct rcu_hlist_head socketmap[USOCKET_TABLE_CAPACITY];

static struct slab msg_slab;
static struct tcache *msg_tcache;
static __thread struct tcache_perthread msg_pt;


static inline int hash_port(uint16_t port)
{
	return hash_crc32c_one(UDP_SEED, port) % USOCKET_TABLE_CAPACITY;
}

static inline bool valid_desc(int desc)
{
	return desc >= 0 && desc < NUSOCKET && usockets[desc];
}

static void packet_handler(void *arg)
{
	struct msg *msg = arg;
	msg->usock->handler(msg->usock->descriptor, msg->m, msg->raddr);
	tcache_free(&msg_pt, msg);
}


void net_rx_udp_usocket(struct mbuf *m, const struct ip_hdr *iphdr, uint16_t len)
{
	int idx;
	uint16_t lport, rport;
	uint32_t laddr, raddr;
	struct msg msg, *msgpt;
	struct rcu_hlist_node *node;
	struct udp_hdr *hdr;
	struct usocket *usock;

	hdr = mbuf_pull_hdr_or_null(m, *hdr);
	if (unlikely(!hdr))
		goto drop;

	if (unlikely(ntoh16(hdr->len) != len))
		goto drop;

	lport = ntoh16(hdr->dst_port);
	rport = ntoh16(hdr->src_port);
	laddr = ntoh32(iphdr->daddr);
	raddr = ntoh32(iphdr->saddr);

	idx = hash_port(lport);

	rcu_read_lock();
	rcu_hlist_for_each(&socketmap[idx], node, true) {
		usock = rcu_hlist_entry(node, struct usocket, link);
		if (usock->laddr.port != lport)
			continue;
		if (usock->laddr.ip && usock->laddr.ip != laddr)
			continue;
		if (usock->raddr.ip && usock->raddr.ip != raddr)
			continue;
		if (usock->raddr.port && usock->raddr.port != rport)
			continue;


		msg.m = m;
		msg.usock = usock;
		msg.raddr.ip = raddr;
		msg.raddr.port = rport;

		if (usock->state == STATE_BOUND_QUEUE) {
			// TODO: is this behavior desired?
			if (unlikely(chan_send(usock->pktq, &msg, false))) {
				log_warn_once("UDP socket queue is full - packets dropped");
				goto unlock;
			}
		} else {
			msgpt = tcache_alloc(&msg_pt);
			if (unlikely(!msgpt))
				goto unlock;
			*msgpt = msg;
			if (unlikely(thread_spawn(packet_handler, msgpt)))
				goto unlock;
		}

		rcu_read_unlock();
		return;

	}


unlock:
	rcu_read_unlock();
drop:
	mbuf_free(m);
}


struct mbuf *usocket_recv_zc(int desc, struct addr *raddr, bool block)
{
	int ret;
	struct msg msg;

	if (unlikely(!valid_desc(desc) || usockets[desc]->state != STATE_BOUND_QUEUE))
		return NULL;

	ret = chan_recv(usockets[desc]->pktq, &msg, block);
	if (unlikely(ret))
		return NULL;

	if (raddr)
		*raddr = msg.raddr;

	return msg.m;
}

int usocket_send_zc(int desc, struct mbuf *m, struct addr raddr)
{
	int ret;
	struct udp_hdr *udphdr;

	if (unlikely(!valid_desc(desc) || usockets[desc]->state == STATE_INIT))
		return -EINVAL;

	unsigned int len = mbuf_length(m) + sizeof(*udphdr);

	udphdr = mbuf_push_hdr(m, *udphdr);
	udphdr->src_port = hton16(usockets[desc]->laddr.port);
	udphdr->dst_port = hton16(raddr.port);
	udphdr->len = hton16(len);
	udphdr->chksum = 0;

	ret = net_tx_ip(m, IPPROTO_UDP, raddr.ip);
	if (unlikely(ret))
		mbuf_pull_hdr(m, *udphdr);

	return ret;

}

ssize_t usocket_recv(int desc, void *buf, size_t len, struct addr *raddr,
		     bool block)
{
	ssize_t actual_len;
	struct mbuf *m = usocket_recv_zc(desc, raddr, block);

	actual_len = min(mbuf_length(m), len);

	memcpy(buf, mbuf_data(m), actual_len);

	mbuf_free(m);

	return actual_len;
}

ssize_t usocket_send(int desc, const void *buf, size_t len, struct addr raddr)
{
	ssize_t actual_len;
	unsigned char *c;

	struct mbuf *r = net_tx_alloc_mbuf();
	if (unlikely(!r))
		return -ENOMEM;

	actual_len = min(MAX_UDP_PAYLOAD, len);

	c = mbuf_put(r, actual_len);
	memcpy(c, buf, actual_len);

	if (unlikely(usocket_send_zc(desc, r, raddr))) {
		mbuf_free(r);
		return -EIO;
	}

	return actual_len;
}


int usocket_connect(int desc, struct addr raddr)
{
	if (unlikely(!valid_desc(desc) || usockets[desc]->state == STATE_INIT))
		return -EINVAL;

	// TODO: somehow make assignment atomic? do we care?
	usockets[desc]->raddr = raddr;

	return 0;
}

int usocket_bind_handler(int desc, struct addr laddr, handler_fn_t fn)
{
	int idx;

	if (unlikely(!valid_desc(desc) || usockets[desc]->state != STATE_INIT || !laddr.port))
		return -EINVAL;

	// TODO: validate laddr
	usockets[desc]->laddr = laddr;
	memset(&usockets[desc]->raddr, 0, sizeof(usockets[desc]->raddr));

	usockets[desc]->state = STATE_BOUND_CALLBACK;
	usockets[desc]->handler = fn;
	idx = hash_port(laddr.port);

	spin_lock(&usocket_lock);
	rcu_hlist_add_head(&socketmap[idx], &usockets[desc]->link);
	spin_unlock(&usocket_lock);

	return 0;
}

int usocket_bind_queue(int desc, struct addr laddr)
{
	int ret, idx;

	if (unlikely(!valid_desc(desc) || usockets[desc]->state != STATE_INIT || !laddr.port))
		return -EINVAL;

	// TODO: validate laddr
	usockets[desc]->laddr = laddr;
	memset(&usockets[desc]->raddr, 0, sizeof(usockets[desc]->raddr));

	usockets[desc]->state = STATE_BOUND_QUEUE;
	usockets[desc]->pktq = smalloc(sizeof(chan_t));
	if (unlikely(!usockets[desc]->pktq))
		return -ENOMEM;
	ret = chan_create(usockets[desc]->pktq, sizeof(struct msg),
			  PKT_QUEUE_CAPACITY);
	if (ret) {
		sfree(usockets[desc]->pktq);
		return ret;
	}

	idx = hash_port(laddr.port);

	spin_lock(&usocket_lock);
	rcu_hlist_add_head(&socketmap[idx], &usockets[desc]->link);
	spin_unlock(&usocket_lock);

	return 0;
}


int usocket_create(void)
{
	int i;

	spin_lock(&usocket_lock);

	for (i = 0; i < NUSOCKET && usockets[i]; i++) ;

	if (i == NUSOCKET) {
		spin_unlock(&usocket_lock);
		return -ENOMEM;
	}

	usockets[i] = smalloc(sizeof(struct usocket));
	spin_unlock(&usocket_lock);

	if (!usockets[i]) {
		return -ENOMEM;
	}

	usockets[i]->descriptor = i;
	usockets[i]->state = STATE_INIT;

	return i;
}

int usocket_init_thread(void)
{
	tcache_init_perthread(msg_tcache, &msg_pt);
	return 0;
}

int usocket_init(void)
{
	int i, ret;

	spin_lock_init(&usocket_lock);

	for (i = 0; i < USOCKET_TABLE_CAPACITY; i++)
		rcu_hlist_init_head(&socketmap[i]);

	ret = slab_create(&msg_slab, "struct msgs", sizeof(struct msg), 0);
	if (ret)
		return ret;

	msg_tcache = slab_create_tcache(&msg_slab, TCACHE_DEFAULT_MAG_SIZE);
	if (!msg_tcache)
		return -ENOMEM;

	return 0;
}
