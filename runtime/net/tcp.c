/*
 * tcp.c - support for Transmission Control Protocol (TCP)
 */

#include <base/stddef.h>
#include <base/kref.h>
#include <base/list.h>
#include <runtime/smalloc.h>
#include <runtime/sync.h>
#include <runtime/thread.h>
#include <runtime/tcp.h>

#include "tcp.h"
#include "defs.h"

struct tcpconn {
	struct trans_entry	e;
	struct tcp_pcb		pcb;
	struct list_node	link;
	spinlock_t		lock;

	/* mbufs waiting to be resequenced */
	struct mbufq		ooo_rxq;

	/* ingress queue */
	size_t			inq_cap;
	size_t			inq_len;
	int			inq_err;
	struct list_head	inq_waiters;
	struct mbufq		inq;

	/* egress queue */
	size_t			outq_cap;
	size_t			outq_len;
	struct list_head	outq_waiters;
};

static tcpconn_t *tcp_conn_create(const struct tcp_hdr *hdr)
{
	/* TODO: implement this */
	return NULL;
}

static void tcp_conn_destroy(tcpconn_t *c)
{
	/* TODO: implement this */
}


/*
 * Support for ingress TCP handling
 */

/* handles ingress packets for TCP sockets */
static void tcp_conn_recv(struct trans_entry *e, struct mbuf *m)
{

}


/*
 * Support for accepting new connections
 */

struct tcpqueue {
	struct trans_entry	e;
	spinlock_t		l;
	struct list_head	waiters;
	struct list_head	conns;
	int			backlog;
	bool			shutdown;
};

static void tcp_queue_recv(struct trans_entry *e, struct mbuf *m)
{
	tcpqueue_t *q = container_of(e, tcpqueue_t, e);
	const struct tcp_hdr *hdr;
	tcpconn_t *c;
	thread_t *th;

	hdr = mbuf_pull_hdr_or_null(m, *hdr);
	if (unlikely(!hdr))
		goto drop;

	c = tcp_conn_create(hdr);
	if (unlikely(!c))
		goto drop;

	spin_lock_np(&q->l);
	if (q->backlog == 0 || q->shutdown) {
		spin_unlock_np(&q->l);
		tcp_conn_destroy(c);
		goto drop;
	}
	list_add_tail(&q->conns, &c->link);
	th = list_pop(&q->waiters, thread_t, link);
	spin_unlock_np(&q->l);
	if (th)
		thread_ready(th);
	return;

drop:
	mbuf_free(m);
}

/* operations for TCP listen queues */
const struct trans_ops tcp_queue_ops = {
	.recv = tcp_queue_recv,
};

/**
 * tcp_listen - creates a socket listening queue for a local address
 * @laddr: the local address to listen on
 * @backlog: the maximum number of unaccepted sockets to queue
 * @q_out: a pointer to store the newly created listening queue
 *
 * Returns 0 if successful, otherwise fails.
 */
int tcp_listen(struct netaddr laddr, int backlog, tcpqueue_t **q_out)
{
	tcpqueue_t *q;
	int ret;

	if (backlog < 1)
		return -EINVAL;

	/* only can support one local IP so far */
	if (laddr.ip == 0)
		laddr.ip = netcfg.addr;
	else if (laddr.ip != netcfg.addr)
		return -EINVAL;

	q = smalloc(sizeof(*q));
	if (!q)
		return -ENOMEM;

	trans_init_3tuple(&q->e, IPPROTO_TCP, &tcp_queue_ops, laddr);
	spin_lock_init(&q->l);
	list_head_init(&q->waiters);
	list_head_init(&q->conns);
	q->backlog = backlog;
	q->shutdown = false;

	ret = trans_table_add(&q->e);
	if (ret) {
		sfree(q);
		return ret;
	}

	*q_out = q;
	return 0;
}

/**
 * tcp_accept - accepts a TCP connection
 * @q: the listen queue to accept the connection on
 * @c_out: a pointer to store the connection
 *
 * Returns 0 if successful, otherwise -EPIPE if the listen queue was closed.
 */
int tcp_accept(tcpqueue_t *q, tcpconn_t **c_out)
{
	tcpconn_t *c;

	spin_lock_np(&q->l);
	while (list_empty(&q->conns) && !q->shutdown) {
		list_add_tail(&q->waiters, &thread_self()->link);
		thread_park_and_unlock_np(&q->l);
		spin_lock_np(&q->l);
	}

	/* was the queue shutdown? */
	if (q->shutdown) {
		spin_unlock_np(&q->l);
		return -EPIPE;
	}

	/* otherwise a new connection is available */
	q->backlog++;
	c = list_pop(&q->conns, tcpconn_t, link);
	assert(c != NULL);
	spin_unlock_np(&q->l);

	*c_out = c;
	return 0;
}

static void __tcp_qshutdown(tcpqueue_t *q)
{
	tcpconn_t *c, *nextc;

	/* mark the listen queue as shutdown */
	spin_lock_np(&q->l);
	BUG_ON(q->shutdown);
	q->shutdown = true;
	spin_unlock_np(&q->l);

	/* prevent ingress receive and error dispatch (after RCU period) */
	trans_table_remove(&q->e);

	/* free all pending connections */
	list_for_each_safe(&q->conns, c, nextc, link) {
		list_del_from(&q->conns, &c->link);
		tcp_conn_destroy(c);
	}
}

/**
 * tcp_qshutdown - disables a TCP listener queue
 * @q: the TCP listener queue to disable
 *
 * All blocking requests on the queue will return -EPIPE.
 */
void tcp_qshutdown(tcpqueue_t *q)
{
	/* shutdown the listen queue */
	__tcp_qshutdown(q);

	/* wake up all pending threads */
	while (true) {
		thread_t *th = list_pop(&q->waiters, thread_t, link);
		if (!th)
			break;
		thread_ready(th);
	}
}

static void tcp_release_queue(struct rcu_head *h)
{
	tcpqueue_t *q = container_of(h, tcpqueue_t, e.rcu);
	sfree(q);
}

/**
 * tcp_qclose - frees a TCP listener queue
 * @q: the TCP listener queue to close
 *
 * WARNING: Only the last reference can safely call this method. Call
 * tcp_qshutdown() first if any threads are sleeping on the queue.
 */
void tcp_qclose(tcpqueue_t *q)
{
	if (!q->shutdown)
		__tcp_qshutdown(q);

	BUG_ON(!list_empty(&q->waiters));
	rcu_free(&q->e.rcu, tcp_release_queue);
}


/*
 * Support for the TCP socket API
 */

int tcp_dial(struct netaddr laddr, struct netaddr raddr, tcpconn_t **c_out)
{
	return -ENOTSUP;
}

struct netaddr tcp_local_addr(tcpconn_t *c)
{
	return c->e.laddr;
}

struct netaddr tcp_remote_addr(tcpconn_t *c)
{
	return c->e.raddr;
}

int tcp_set_buffers(tcpconn_t *c, size_t read_len, size_t write_len)
{
	return -ENOTSUP;
}

ssize_t tcp_read(tcpconn_t *c, void *buf, size_t len)
{
	return -ENOTSUP;
}

ssize_t tcp_write(tcpconn_t *c, const void *buf, size_t len)
{
	return -ENOTSUP;
}

ssize_t tcp_readv(const struct iovec *iov, int iovcnt)
{
	return -ENOTSUP;
}

ssize_t tcp_writev(const struct iovec *iov, int iovcnt)
{
	return -ENOTSUP;
}

void tcp_shutdown(tcpconn_t *c, int how)
{

}

void tcp_close(tcpconn_t *c)
{

}
