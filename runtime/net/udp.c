/*
 * udp.c - support for User Datagram Protocol (UDP)
 */

#include <string.h>

#include <base/hash.h>
#include <base/smalloc.h>
#include <base/kref.h>
#include <runtime/rculist.h>
#include <runtime/thread.h>
#include <runtime/udp.h>

#include "defs.h"

#define UDP_SEED		0x48FA8BC1
#define UDP_TABLE_SIZE		1024
#define UDP_IN_DEFAULT_CAP	512
#define UDP_OUT_DEFAULT_CAP	2048

/* ephemeral port definitions (IANA suggested range) */
#define MIN_EPHEMERAL		49152
#define MAX_EPHEMERAL		65535

enum {
	/* match on source IP and port */
	UDP_MATCH_2TUPLE = 0,
	/* match on source IP and port + destination IP and port */
	UDP_MATCH_4TUPLE,
};

static inline uint32_t udp_hash_2tuple(struct udpaddr laddr)
{
	return hash_crc32c_one(UDP_SEED,
		(uint64_t)laddr.ip | ((uint64_t)laddr.port << 32));
}

static inline uint32_t udp_hash_4tuple(struct udpaddr laddr,
				       struct udpaddr raddr)
{
	return hash_crc32c_two(UDP_SEED,
		(uint64_t)laddr.ip | ((uint64_t)laddr.port << 32),
		(uint64_t)raddr.ip | ((uint64_t)raddr.port << 32));
}

struct udp_entry;

struct udp_ops {
	/* receive an ingress UDP packet */
	void (*recv) (struct udp_entry *e, struct mbuf *m);
	/* propagate a network error */
	void (*err) (struct udp_entry *e, int err);
};

struct udp_entry {
	int			match;
	struct udpaddr		laddr;
	struct udpaddr		raddr;
	struct rcu_hlist_node	link;
	struct rcu_head		rcu;
	const struct udp_ops	*ops;
};

static DEFINE_SPINLOCK(udp_lock);
static struct rcu_hlist_head udp_table[UDP_TABLE_SIZE];

/**
 * udp_table_add - adds an entry to the UDP match table
 * @e: the entry to add
 *
 * Returns 0 if successful, or -EADDRINUSE if a conflicting entry is already in
 * the table, or -EINVAL if the local port is zero.
 */
static int udp_table_add(struct udp_entry *e)
{
	struct udp_entry *pos;
	struct rcu_hlist_node *node;
	uint32_t idx;

	/* port zero is reserved for ephemeral port auto-assign */
	if (e->laddr.port == 0)
		return -EINVAL;

	assert(e->match == UDP_MATCH_2TUPLE || e->match == UDP_MATCH_4TUPLE);
	if (e->match == UDP_MATCH_2TUPLE)
		idx = udp_hash_2tuple(e->laddr);
	else
		idx = udp_hash_4tuple(e->laddr, e->raddr);
	idx %= UDP_TABLE_SIZE;

	spin_lock(&udp_lock);
	rcu_hlist_for_each(&udp_table[idx], node, true) {
		pos = rcu_hlist_entry(node, struct udp_entry, link);
		if (pos->match != e->match)
			continue;
		if (e->match == UDP_MATCH_2TUPLE &&
		    e->laddr.ip == pos->laddr.ip &&
		    e->laddr.port == pos->laddr.port) {
			spin_unlock(&udp_lock);
			return -EADDRINUSE;
		} else if (e->laddr.ip == pos->laddr.ip &&
			   e->laddr.port == pos->laddr.port &&
			   e->raddr.ip == pos->raddr.ip &&
			   e->raddr.port == pos->raddr.port) {
			spin_unlock(&udp_lock);
			return -EADDRINUSE;
		}
	}
	rcu_hlist_add_head(&udp_table[idx], &e->link);
	spin_unlock(&udp_lock);

	return 0;
}

/**
 * udp_table_add_with_ephemeral_port - adds an entry to the UDP match table
 * while automatically selecting the local port number
 * @e: the entry to add
 *
 * We use algorithm 3 from RFC 6056.
 *
 * Returns 0 if successful or -EADDRNOTAVAIL if all ports are taken.
 */
static int udp_table_add_with_ephemeral_port(struct udp_entry *e)
{
	uint16_t offset, next_ephemeral = 0;
	uint16_t num_ephemeral = MAX_EPHEMERAL - MIN_EPHEMERAL + 1;
	int ret;

	if (e->match != UDP_MATCH_4TUPLE)
		return -EINVAL;

	e->laddr.port = 0;
	offset = udp_hash_4tuple(e->laddr, e->raddr);
	while (next_ephemeral < num_ephemeral) {
		uint32_t port = MIN_EPHEMERAL +
				(next_ephemeral++ + offset) % num_ephemeral;
		e->laddr.port = port;
		ret = udp_table_add(e);
		if (!ret)
			return 0;
	}

	return -EADDRNOTAVAIL;
}

/**
 * udp_table_remove - removes an entry from the UDP match table
 * @e: the entry to remove
 *
 * The caller is responsible for eventually freeing the object with rcu_free().
 */
static void udp_table_remove(struct udp_entry *e)
{
	spin_lock(&udp_lock);
	rcu_hlist_del(&e->link);
	spin_unlock(&udp_lock);
}

/**
 * udp_table_lookup - retrieves a matching UDP entry
 * @lip: the local IP address
 * @rip: the remote IP address
 * @lport: the local port
 * @rport: the remote port
 * @full: if true, the full 4-tuple must match
 *
 * Must be called from inside an RCU critical section.
 *
 * Returns a UDP entry or NULL if no matches were found.
 */
static struct udp_entry *
udp_table_lookup(uint32_t lip, uint32_t rip,
		 uint16_t lport, uint16_t rport, bool full)
{
	struct udpaddr laddr, raddr;
	struct udp_entry *e;
	struct rcu_hlist_node *node;
	uint32_t idx;

	/* for input to hash functions */
	laddr.ip = lip;
	laddr.port = lport;
	raddr.ip = rip;
	raddr.port = rport;

	/* first try a 4-tuple match */
	idx = udp_hash_4tuple(laddr, raddr) % UDP_TABLE_SIZE;
	rcu_hlist_for_each(&udp_table[idx], node, false) {
		e = rcu_hlist_entry(node, struct udp_entry, link);
		if (e->match != UDP_MATCH_4TUPLE)
			continue;
		if (e->laddr.ip == lip && e->laddr.port == lport &&
		    e->raddr.ip == rip && e->raddr.port == rport)
			return e;
	}

	if (full)
		return NULL;

	/* then fallback to a 2-tuple match */
	idx = udp_hash_2tuple(laddr) % UDP_TABLE_SIZE;
	rcu_hlist_for_each(&udp_table[idx], node, false) {
		e = rcu_hlist_entry(node, struct udp_entry, link);
		if (e->match != UDP_MATCH_2TUPLE)
			continue;
		if (e->laddr.ip == lip && e->laddr.port == lport)
			return e;
	}

	return NULL;
}

/**
 * net_rx_udp - receive an ingress UDP packet from the netstack
 * @m: the mbuf to receive
 * @iphdr: the IP header of the mbuf
 * @len: the remaining length of the mbuf
 *
 * The mbuf data pointer starts at the UDP header.
 */
void net_rx_udp(struct mbuf *m, const struct ip_hdr *iphdr, uint16_t len)
{
	const struct udp_hdr *udphdr;
	struct udp_entry *e;

	mbuf_mark_transport_offset(m);
	udphdr = mbuf_pull_hdr_or_null(m, *udphdr);
	if (unlikely(!udphdr))
		goto drop;
	if (unlikely(ntoh16(udphdr->len) != len))
		goto drop;

	rcu_read_lock();
	e = udp_table_lookup(ntoh32(iphdr->daddr), ntoh32(iphdr->saddr),
			     ntoh16(udphdr->dst_port), ntoh16(udphdr->src_port),
			     false);
	if (!e) {
		rcu_read_unlock();
		goto drop;
	}
	assert(e->ops->recv != NULL);
	e->ops->recv(e, m);
	rcu_read_unlock();

	return;

drop:
	mbuf_free(m);
}

/**
 * udp_error - reports a network error
 * @m: the mbuf that triggered the error
 * @iphdr: the IP header in the mbuf that triggered the error
 * @err: the suggested ernno to report
 */
void udp_error(struct mbuf *m, const struct ip_hdr *iphdr, int err)
{
	const struct udp_hdr *udphdr;
	struct udp_entry *e;

	/* WARNING: can't pull, full header may not be available (e.g. ICMP) */
	udphdr = (struct udp_hdr *)mbuf_data(m);

	rcu_read_lock();
	e = udp_table_lookup(ntoh32(iphdr->saddr), ntoh32(iphdr->daddr),
			     ntoh16(udphdr->src_port), ntoh16(udphdr->dst_port),
			     true);
	if (e && e->ops->err)
		e->ops->err(e, err);
	rcu_read_unlock();
}

static int udp_send_raw(struct mbuf *m, size_t len,
			struct udpaddr laddr, struct udpaddr raddr)
{
	struct udp_hdr *udphdr;

	/* write UDP header */
	udphdr = mbuf_push_hdr(m, *udphdr);
	udphdr->src_port = hton16(laddr.port);
	udphdr->dst_port = hton16(raddr.port);
	udphdr->len = hton16(len + sizeof(*udphdr));
	udphdr->chksum = 0;

	/* send the IP packet */
	return net_tx_ip(m, IPPROTO_UDP, raddr.ip);
}


/*
 * UDP Socket Support
 */

struct udpconn {
	struct udp_entry	e;
	bool			shutdown;

	/* ingress support */
	spinlock_t		inq_lock;
	int			inq_cap;
	int			inq_len;
	int			inq_err;
	struct list_head	inq_waiters;
	struct mbufq		inq;

	/* egress support */
	spinlock_t		outq_lock;
	bool			outq_free;
	int			outq_cap;
	int			outq_len;
	struct list_head	outq_waiters;
};

/* handles ingress packets for UDP sockets */
static void udp_conn_recv(struct udp_entry *e, struct mbuf *m)
{
	udpconn_t *c = container_of(e, udpconn_t, e);
	thread_t *th;

	spin_lock(&c->inq_lock);
	/* drop packet if the ingress queue is full */
	if (c->inq_len >= c->inq_cap || c->shutdown) {
		spin_unlock(&c->inq_lock);
		mbuf_drop(m);
		return;
	}

	/* enqueue the packet on the ingress queue */
	mbufq_push_tail(&c->inq, m);
	c->inq_len++;

	/* wake up a waiter */
	th = list_pop(&c->inq_waiters, thread_t, link);
	spin_unlock(&c->inq_lock);

	if (th)
		thread_ready(th);
}

/* handles network errors for UDP sockets */
static void udp_conn_err(struct udp_entry *e, int err)
{
	udpconn_t *c = container_of(e, udpconn_t, e);
	thread_t *th;
	struct list_head tmp;

	list_head_init(&tmp);

	spin_lock(&c->inq_lock);
	c->inq_err = err;
	list_append_list(&tmp, &c->inq_waiters);
	spin_unlock(&c->inq_lock);

	while (true) {
		th = list_pop(&tmp, thread_t, link);
		if (!th)
			break;
		thread_ready(th);
	}
}

/* operations for UDP sockets */
const struct udp_ops udp_conn_ops = {
	.recv = udp_conn_recv,
	.err = udp_conn_err,
};

static void udp_init_conn(udpconn_t *c)
{
	c->shutdown = false;
	c->e.ops = &udp_conn_ops;

	/* initialize ingress fields */
	spin_lock_init(&c->inq_lock);
	c->inq_cap = UDP_IN_DEFAULT_CAP;
	c->inq_len = 0;
	c->inq_err = 0;
	list_head_init(&c->inq_waiters);
	mbufq_init(&c->inq);

	/* initialize egress fields */
	spin_lock_init(&c->outq_lock);
	c->outq_free = false;
	c->outq_cap = UDP_OUT_DEFAULT_CAP;
	c->outq_len = 0;
	list_head_init(&c->outq_waiters);
}

static void udp_finish_release_conn(struct rcu_head *h)
{
	udpconn_t *c = container_of(h, udpconn_t, e.rcu);
	sfree(c);
}

static void udp_release_conn(udpconn_t *c)
{
	assert(list_empty(&c->inq_waiters) && list_empty(&c->outq_waiters));
	assert(mbufq_empty(&c->inq));
	rcu_free(&c->e.rcu, udp_finish_release_conn);
}

/**
 * udp_dial - creates a UDP socket between a local and remote address
 * @laddr: the local UDP address
 * @raddr: the remote UDP address
 * @c_out: a pointer to store the UDP socket (if successful)
 *
 * Returns 0 if success, otherwise fail.
 */
int udp_dial(struct udpaddr laddr, struct udpaddr raddr, udpconn_t **c_out)
{
	udpconn_t *c;
	int ret;

	/* only can support one local IP so far */
	if (laddr.ip == 0)
		laddr.ip = netcfg.addr;
	else if (laddr.ip != netcfg.addr)
		return -EINVAL;

	c = smalloc(sizeof(*c));
	if (!c)
		return -ENOMEM;

	udp_init_conn(c);
	c->e.match = UDP_MATCH_4TUPLE;
	c->e.laddr = laddr;
	c->e.raddr = raddr;

	if (laddr.port == 0)
		ret = udp_table_add_with_ephemeral_port(&c->e);
	else
		ret = udp_table_add(&c->e);
	if (ret) {
		sfree(c);
		return ret;
	}

	*c_out = c;
	return 0;
}

/**
 * udp_listen - creates a UDP socket listening to a local address
 * @laddr: the local UDP address
 * @c_out: a pointer to store the UDP socket (if successful)
 *
 * Returns 0 if success, otherwise fail.
 */
int udp_listen(struct udpaddr laddr, udpconn_t **c_out)
{
	udpconn_t *c;
	int ret;

	/* only can support one local IP so far */
	if (laddr.ip == 0)
		laddr.ip = netcfg.addr;
	else if (laddr.ip != netcfg.addr)
		return -EINVAL;

	c = smalloc(sizeof(*c));
	if (!c)
		return -ENOMEM;

	udp_init_conn(c);
	c->e.match = UDP_MATCH_2TUPLE;
	c->e.laddr = laddr;
	c->e.raddr.ip = 0;
	c->e.raddr.port = 0;

	ret = udp_table_add(&c->e);
	if (ret) {
		sfree(c);
		return ret;
	}

	*c_out = c;
	return 0;
}

/**
 * udp_local_addr - gets the local address of the socket
 * @c: the UDP socket
 */
struct udpaddr udp_local_addr(udpconn_t *c)
{
	return c->e.laddr;
}

/**
 * udp_remote_addr - gets the remote address of the socket
 * @c: the UDP socket
 *
 * A UDP socket may not have a remote address attached. If so, the IP and
 * port will be set to zero.
 */
struct udpaddr udp_remote_addr(udpconn_t *c)
{
	return c->e.raddr;
}

/**
 * udp_set_buffers - changes send and receive buffer sizes
 * @c: the UDP socket
 * @read_mbufs: the maximum number of read mbufs to buffer
 * @write_mbufs: the maximum number of write mbufs to buffer
 *
 * Returns 0 if the inputs were valid.
 */
int udp_set_buffers(udpconn_t *c, int read_mbufs, int write_mbufs)
{
	c->inq_cap = read_mbufs;
	c->outq_cap = write_mbufs;

	/* TODO: free mbufs that go over new limits? */
	return 0;
}

/**
 * udp_read_from - reads from a UDP socket
 * @c: the UDP socket
 * @buf: a buffer to store the datagram
 * @len: the size of @buf
 * @raddr: a pointer to store the remote address of the datagram (if not NULL)
 *
 * WARNING: This a blocking function. It will wait until a datagram is
 * available, an error occurs, or the socket is shutdown.
 *
 * Returns the number of bytes in the datagram, or @len if the datagram
 * is >= @len in size. If the socket has been shutdown, returns 0.
 */
ssize_t udp_read_from(udpconn_t *c, void *buf, size_t len,
                      struct udpaddr *raddr)
{
	ssize_t ret;
	struct mbuf *m;

	spin_lock(&c->inq_lock);

	/* block until there is an actionable event */
	while (mbufq_empty(&c->inq) && !c->inq_err && !c->shutdown) {
		list_add_tail(&c->inq_waiters, &thread_self()->link);
		thread_park_and_unlock(&c->inq_lock);
		spin_lock(&c->inq_lock);
	}

	/* is the socket shutdown? */
	if (c->shutdown) {
		spin_unlock(&c->inq_lock);
		return 0;
	}

	/* propagate error status code if an error was detected */
	if (c->inq_err) {
		spin_unlock(&c->inq_lock);
		return -c->inq_err;
	}

	/* pop an mbuf and deliver the payload */
	m = mbufq_pop_head(&c->inq);
	c->inq_len--;
	spin_unlock(&c->inq_lock);

	ret = min(len, mbuf_length(m));
	memcpy(buf, mbuf_data(m), ret);
	if (raddr) {
		struct ip_hdr *iphdr = mbuf_network_hdr(m, *iphdr);
		struct udp_hdr *udphdr = mbuf_transport_hdr(m, *udphdr);
		raddr->ip = ntoh32(iphdr->saddr);
		raddr->port = ntoh16(udphdr->src_port);
		if (c->e.match == UDP_MATCH_4TUPLE) {
			assert(c->e.raddr.ip == raddr->ip &&
			       c->e.raddr.port == raddr->port);
		}
	}
	mbuf_free(m);
	return ret;
}

static void udp_tx_release_mbuf(struct mbuf *m)
{
	udpconn_t *c = (udpconn_t *)m->release_data;
	thread_t *th;
	bool free_conn;

	spin_lock(&c->outq_lock);
	c->outq_len--;
	th = list_pop(&c->outq_waiters, thread_t, link);
	free_conn = (c->outq_free && c->outq_len == 0);
	spin_unlock(&c->outq_lock);
	if (th)
		thread_ready(th);

	net_tx_release_mbuf(m);
	if (free_conn)
		udp_release_conn(c);
}

/**
 * udp_write_to - writes to a UDP socket
 * @c: the UDP socket
 * @buf: a buffer from which to load the payload
 * @len: the length of the payload
 * @raddr: the remote address of the datagram (if not NULL)
 *
 * WARNING: This a blocking function. It will wait until space in the transmit
 * buffer is available or the socket is shutdown.
 *
 * Returns the number of payload bytes sent in the datagram. If an error
 * occurs, returns < 0 to indicate the error code.
 */
ssize_t udp_write_to(udpconn_t *c, const void *buf, size_t len,
                     const struct udpaddr *raddr)
{
	struct udpaddr addr;
	ssize_t ret;
	struct mbuf *m;
	void *payload;

	if (len > UDP_MAX_PAYLOAD)
		return -EMSGSIZE;
	if (!raddr) {
		if (c->e.match == UDP_MATCH_2TUPLE)
			return -EDESTADDRREQ;
		addr = c->e.raddr;
	} else {
		addr = *raddr;
	}

	spin_lock(&c->outq_lock);

	/* block until there is an actionable event */
	while (c->outq_len >= c->outq_cap && !c->shutdown) {
		list_add_tail(&c->outq_waiters, &thread_self()->link);
		thread_park_and_unlock(&c->outq_lock);
		spin_lock(&c->outq_lock);
	}

	/* is the socket shutdown? */
	if (c->shutdown) {
		spin_unlock(&c->outq_lock);
		return -ESHUTDOWN;
	}

	c->outq_len++;
	spin_unlock(&c->outq_lock);

	m = net_tx_alloc_mbuf();
	if (unlikely(!m))
		return -ENOBUFS;

	/* write datagram payload */
	payload = mbuf_put(m, len);
	memcpy(payload, buf, len);

	/* override mbuf release method */
	m->release = udp_tx_release_mbuf;
	m->release_data = (unsigned long)c;

	ret = udp_send_raw(m, len, c->e.laddr, addr);
	if (unlikely(ret)) {
		net_tx_release_mbuf(m);
		return ret;
	}

	return len;
}

/**
 * udp_read - reads from a UDP socket
 * @c: the UDP socket
 * @buf: a buffer to store the datagram
 * @len: the size of @buf
 *
 * WARNING: This a blocking function. It will wait until a datagram is
 * available, an error occurs, or the socket is shutdown.
 *
 * Returns the number of bytes in the datagram, or @len if the datagram
 * is >= @len in size. If the socket has been shutdown, returns 0.
 */
ssize_t udp_read(udpconn_t *c, void *buf, size_t len)
{
	return udp_read_from(c, buf, len, NULL);
}

/**
 * udp_write - writes to a UDP socket
 * @c: the UDP socket
 * @buf: the payload to send
 * @len: the length of the payload
 *
 * WARNING: This a blocking function. It will wait until space in the transmit
 * buffer is available or the socket is shutdown.
 *
 * Returns the number of payload bytes sent in the datagram. If an error
 * occurs, returns < 0 to indicate the error code.
 */
ssize_t udp_write(udpconn_t *c, const void *buf, size_t len)
{
	return udp_write_to(c, buf, len, NULL);
}

/**
 * udp_shutdown - disables a UDP socket
 * @c: the socket to disable
 *
 * All blocking requests on the socket will return and future ingress and
 * egress packets will be aborted.
 */
void udp_shutdown(udpconn_t *c)
{
	struct list_head tmp;
	struct mbufq q;
	thread_t *th;

	list_head_init(&tmp);
	mbufq_init(&q);

	BUG_ON(c->shutdown);
	c->shutdown = true;

	/* prevent ingress receive and error dispatch (after RCU period) */
	udp_table_remove(&c->e);

	/* drain ingress */
	spin_lock(&c->inq_lock);
	list_append_list(&tmp, &c->inq_waiters);
	mbufq_merge_to_tail(&q, &c->inq);
	spin_unlock(&c->inq_lock);

	/* drain egress */
	spin_lock(&c->outq_lock);
	list_append_list(&tmp, &c->outq_waiters);
	spin_unlock(&c->outq_lock);

	/* wake all blocked threads */
	while (true) {
		th = list_pop(&tmp, thread_t, link);
		if (!th)
			break;
		thread_ready(th);
	}

	/* free all in-flight mbufs */
	while (true) {
		struct mbuf *m = mbufq_pop_head(&q);
		if (!m)
			break;
		mbuf_free(m);
	}
}

/**
 * udp_close - frees a UDP socket
 * @c: the socket to free
 *
 * If the socket is not shutdown, this function will first call udp_shutdown().
 * WARNING: Do not reference the connection after calling this function, as its
 * backing memory will be freed.
 */
void udp_close(udpconn_t *c)
{
	bool free_conn;

	if (!c->shutdown)
		udp_shutdown(c);

	spin_lock(&c->outq_lock);
	free_conn = c->outq_len == 0;
	spin_unlock(&c->outq_lock);

	if (free_conn)
		udp_release_conn(c);
}


/*
 * Parallel API
 */

struct udpspawner {
	struct udp_entry	e;
	udpspawn_fn_t		fn;
};

/* handles ingress packets with parallel threads */
static void udp_par_recv(struct udp_entry *e, struct mbuf *m)
{
	udpspawner_t *s = container_of(e, udpspawner_t, e);
	struct ip_hdr *iphdr = mbuf_network_hdr(m, *iphdr);
	struct udp_hdr *udphdr = mbuf_transport_hdr(m, *udphdr);
	struct udp_spawn_data *d;
	thread_t *th;

	th = thread_create_with_buf((thread_fn_t)s->fn,
				    (void **)&d, sizeof(*d));
	if (unlikely(!th)) {
		mbuf_drop(m);
		return;
	}

	d->buf = mbuf_data(m);
	d->len = mbuf_length(m);
	d->laddr = e->laddr;
	d->raddr.ip = ntoh32(iphdr->saddr);
	d->raddr.port = ntoh16(udphdr->src_port);
	d->release_data = m;
	thread_ready(th);
}

/* operations for UDP spawners */
const struct udp_ops udp_par_ops = {
	.recv = udp_par_recv,
};

/**
 * udp_create_spawner - creates a UDP spawner for ingress datagrams
 * @laddr: the local address to bind to
 * @fn: a handler function for each datagram
 * @s_out: if successful, set to a pointer to the spawner
 *
 * Returns 0 if successful, otherwise fail.
 */
int udp_create_spawner(struct udpaddr laddr, udpspawn_fn_t fn,
		       udpspawner_t **s_out)
{
	udpspawner_t *s;
	int ret;

	/* only can support one local IP so far */
	if (laddr.ip == 0)
		laddr.ip = netcfg.addr;
	else if (laddr.ip != netcfg.addr)
		return -EINVAL;

	s = smalloc(sizeof(*s));
	if (!s)
		return -ENOMEM;

	s->e.match = UDP_MATCH_2TUPLE;
	s->e.laddr = laddr;
	s->e.ops = &udp_par_ops;
	s->fn = fn;

	ret = udp_table_add(&s->e);
	if (ret) {
		sfree(s);
		return ret;
	}

	*s_out = s;
	return 0;
}

static void udp_release_spawner(struct rcu_head *h)
{
	udpspawner_t *s = container_of(h, udpspawner_t, e.rcu);
	sfree(s);
}

/**
 * udp_destroy_spawner - unregisters and frees a UDP spawner
 * @s: the spawner to free
 */
void udp_destroy_spawner(udpspawner_t *s)
{
	udp_table_remove(&s->e);
	rcu_free(&s->e.rcu, udp_release_spawner);
}

/**
 * udp_send - sends a UDP datagram
 * @buf: the payload to send
 * @len: the length of the payload
 * @laddr: the local UDP address
 * @raddr: the remote UDP address
 *
 * Returns the number of payload bytes sent in the datagram. If an error
 * occurs, returns < 0 to indicate the error code.
 */
ssize_t udp_send(const void *buf, size_t len,
		 struct udpaddr laddr, struct udpaddr raddr)
{
	void *payload;
	struct mbuf *m;
	int ret;

	if (len > UDP_MAX_PAYLOAD)
		return -EMSGSIZE;
	if (laddr.ip == 0)
		laddr.ip = netcfg.addr;
	else if (laddr.ip != netcfg.addr)
		return -EINVAL;
	if (laddr.port == 0)
		return -EINVAL;

	m = net_tx_alloc_mbuf();
	if (unlikely(!m))
		return -ENOBUFS;

	/* write datagram payload */
	payload = mbuf_put(m, len);
	memcpy(payload, buf, len);

	ret = udp_send_raw(m, len, laddr, raddr);
	if (unlikely(ret)) {
		mbuf_free(m);
		return ret;
	}

	return len;
}

ssize_t udp_sendv(const struct iovec *iov, int iovcnt, struct udpaddr laddr,
	       struct udpaddr raddr)
{
	struct mbuf *m;
	int i, ret;
	ssize_t len = 0;

	if (laddr.ip == 0)
		laddr.ip = netcfg.addr;
	else if (laddr.ip != netcfg.addr)
		return -EINVAL;
	if (laddr.port == 0)
		return -EINVAL;

	m = net_tx_alloc_mbuf();
	if (unlikely(!m))
		return -ENOBUFS;

	/* write datagram payload */
	for (i = 0; i < iovcnt; i++) {
		len += iov[i].iov_len;
		if (unlikely(len > UDP_MAX_PAYLOAD)) {
			mbuf_free(m);
			return -EMSGSIZE;
		}
		memcpy(mbuf_put(m, iov[i].iov_len),
		       iov[i].iov_base, iov[i].iov_len);
	}

	ret = udp_send_raw(m, len, laddr, raddr);
	if (unlikely(ret)) {
		mbuf_free(m);
		return ret;
	}

	return len;
}

/**
 * udp_spawn_data_release - frees the datagram buffer for a spawner thread
 * @release_data: the release data pointer
 *
 * Must be called when finished with the buffer passed to the spawner thread.
 */
void udp_spawn_data_release(void *release_data)
{
	struct mbuf *m = release_data;
	mbuf_free(m);
}

/**
 * udp_init - initializes the UDP stack
 *
 * Returns 0 (always successful).
 */
int udp_init(void)
{
	int i;

	spin_lock_init(&udp_lock);

	for (i = 0; i < UDP_TABLE_SIZE; i++)
		rcu_hlist_init_head(&udp_table[i]);

	return 0;
}
