/*
 * tcp.c - support for Transmission Control Protocol (RFC 793)
 */

#include <string.h>

#include <base/stddef.h>
#include <base/hash.h>
#include <runtime/smalloc.h>
#include <runtime/thread.h>
#include <runtime/tcp.h>

#include "tcp.h"


/*
 * Ingress path
 */

/* handles ingress packets for TCP sockets */
static void tcp_conn_recv(struct trans_entry *e, struct mbuf *m)
{

}

/* handles network errors for TCP sockets */
static void tcp_conn_err(struct trans_entry *e, int err)
{

}

/* operations for TCP sockets */
const struct trans_ops tcp_conn_ops = {
	.recv = tcp_conn_recv,
	.err = tcp_conn_err,
};


/*
 * Connection initialization
 */

/**
 * tcp_conn_alloc - allocates a TCP connection struct
 * @state: the initial PCB state of the connection
 *
 * Returns a connection, or NULL if out of memory.
 */
tcpconn_t *tcp_conn_alloc(int state)
{
	tcpconn_t *c;

	c = smalloc(sizeof(*c));
	if (!c)
		return NULL;

	/* general fields */
	memset(&c->pcb, 0, sizeof(c->pcb));
	spin_lock_init(&c->lock);

	/* ingress fields */
	c->rx_err = 0;
	waitq_init(&c->rx_wq);
	mbufq_init(&c->rxq_ooo);
	mbufq_init(&c->rxq);

	/* egress fields */
	c->tx_exclusive = false;
	waitq_init(&c->tx_wq);
	c->tx_last_ack = 0;
	c->tx_last_win = 0;
	c->tx_pending = NULL;
	mbufq_init(&c->txq);

	/* initialize egress half of PCB */
	c->pcb.state = state;
	c->pcb.iss = rand_crc32c(0xDEADBEEF); /* TODO: not secure */
	c->pcb.snd_nxt = c->pcb.iss;
	c->pcb.snd_una = c->pcb.iss;
	c->pcb.rcv_wnd = TCP_WIN;

	return c;
}

/**
 * tcp_conn_attach - attaches a connection to the transport layer
 * @c: the connection to attach
 * @laddr: the local network address
 * @raddr: the remote network address
 *
 * After calling this function, if successful, ingress packets and errors will
 * be delivered.
 */
int tcp_conn_attach(tcpconn_t *c, struct netaddr laddr, struct netaddr raddr)
{
	/* register the connection with the transport layer */
	trans_init_5tuple(&c->e, IPPROTO_TCP, &tcp_conn_ops, laddr, raddr);
	if (laddr.port == 0)
		return trans_table_add_with_ephemeral_port(&c->e);
	return trans_table_add(&c->e);
}

static void tcp_conn_release(struct rcu_head *h)
{
	tcpconn_t *c = container_of(h, tcpconn_t, e.rcu);
	mbufq_release(&c->rxq_ooo);
	mbufq_release(&c->rxq);
	mbufq_release(&c->txq);
	sfree(c);
}

/**
 * tcp_conn_destroy - tears down a frees a TCP connection
 * @c: the connection to destroy
 */
void tcp_conn_destroy(tcpconn_t *c)
{
	trans_table_remove(&c->e);
	rcu_free(&c->e.rcu, tcp_conn_release);
}


/*
 * Support for accepting new connections
 */

struct tcpqueue {
	struct trans_entry	e;
	spinlock_t		l;
	waitq_t			wq;
	struct list_head	conns;
	int			backlog;
	bool			shutdown;
};

static void tcp_queue_recv(struct trans_entry *e, struct mbuf *m)
{
	tcpqueue_t *q = container_of(e, tcpqueue_t, e);
	struct netaddr laddr, raddr;
	const struct ip_hdr *iphdr;
	const struct tcp_hdr *tcphdr;
	tcpconn_t *c;
	thread_t *th;
	int ret;

	/* find header offsets */
	iphdr = mbuf_network_hdr(m, *iphdr);
	tcphdr = mbuf_pull_hdr_or_null(m, *tcphdr);
	if (unlikely(!tcphdr))
		goto done;

	/* calculate local and remote network addresses */
	laddr = q->e.laddr;
	raddr.ip = ntoh32(iphdr->saddr);
	raddr.port = ntoh16(tcphdr->sport);

	/* do exactly what RFC 793 says */
	if ((tcphdr->flags & TCP_RST) > 0)
		goto done;
	if ((tcphdr->flags & TCP_ACK) > 0) {
		tcp_tx_raw_rst(laddr, raddr, ntoh32(tcphdr->ack));
		goto done;
	}
	if ((tcphdr->flags & TCP_SYN) == 0)
		goto done;

	/* TODO: the spec requires us to enqueue but not post any data */
	if (ntoh16(iphdr->len) - sizeof(*iphdr) != sizeof(*tcphdr))
		goto done;

	/* make sure the connection queue isn't full */
	spin_lock_np(&q->l);
	if (unlikely(q->backlog == 0 || q->shutdown)) {
		spin_unlock_np(&q->l);
		goto done;
	}
	q->backlog--;
	spin_unlock_np(&q->l);

	/* we have a valid SYN packet, initialize a new connection */
	c = tcp_conn_alloc(TCP_STATE_SYN_RECEIVED);
	if (unlikely(!c))
		goto give_back;
	c->pcb.irs = ntoh32(tcphdr->seq);
	c->pcb.rcv_nxt = c->pcb.irs + 1;

	/*
	 * Attach the connection to the transport layer. From this point onward
	 * ingress packets can be dispatched to the connection.
	 */
	ret = tcp_conn_attach(c, laddr, raddr);
	if (unlikely(!ret)) {
		sfree(c);
		goto give_back;
	}

	/* finally, send a SYN/ACK to the remote host */
	ret = tcp_tx_ctl(c, TCP_SYN | TCP_ACK);
	if (unlikely(!ret)) {
		tcp_conn_destroy(c);
		goto done;
	}

	/* wake a thread to accept the connection */
	spin_lock_np(&q->l);
	list_add_tail(&q->conns, &c->link);
	th = waitq_signal(&q->wq, &q->l);
	spin_unlock_np(&q->l);
	waitq_signal_finish(th);
	goto done;

give_back:
	spin_lock_np(&q->l);
	q->backlog++;
	spin_unlock_np(&q->l);
done:
	mbuf_free(m);
}

/* operations for TCP listen queues */
const struct trans_ops tcp_queue_ops = {
	.recv = tcp_queue_recv,
};

/**
 * tcp_listen - creates a TCP listening queue for a local address
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
	waitq_init(&q->wq);
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
	while (list_empty(&q->conns) && !q->shutdown)
		waitq_wait(&q->wq, &q->l);

	/* was the queue drained and shutdown? */
	if (list_empty(&q->conns) && q->shutdown) {
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
	/* mark the listen queue as shutdown */
	spin_lock_np(&q->l);
	BUG_ON(q->shutdown);
	q->shutdown = true;
	spin_unlock_np(&q->l);

	/* prevent ingress receive and error dispatch (after RCU period) */
	trans_table_remove(&q->e);
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
	waitq_release(&q->wq);
}

static void tcp_queue_release(struct rcu_head *h)
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
	tcpconn_t *c, *nextc;

	if (!q->shutdown)
		__tcp_qshutdown(q);

	BUG_ON(!waitq_empty(&q->wq));

	/* free all pending connections */
	list_for_each_safe(&q->conns, c, nextc, link) {
		list_del_from(&q->conns, &c->link);
		tcp_conn_destroy(c);
	}

	rcu_free(&q->e.rcu, tcp_queue_release);
}


/*
 * Support for the TCP socket API
 */

/**
 * tcp_dial - opens a TCP connection, creating a new socket
 * @laddr: the local address
 * @raddr: the remote address
 * @c_out: a pointer to store the new connection
 *
 * Returns 0 if successful, otherwise fail.
 */
int tcp_dial(struct netaddr laddr, struct netaddr raddr, tcpconn_t **c_out)
{
	tcpconn_t *c;
	int ret;

	/* create and initialize a connection */
	c = tcp_conn_alloc(TCP_STATE_SYN_SENT);
	if (unlikely(!c))
		return -ENOMEM;

	/*
	 * Attach the connection to the transport layer. From this point onward
	 * ingress packets can be dispatched to the connection.
	 */
	ret = tcp_conn_attach(c, laddr, raddr);
	if (unlikely(!ret)) {
		sfree(c);
		return ret;
	}

	/* finally, send a SYN to the remote host */
	ret = tcp_tx_ctl(c, TCP_SYN);
	if (unlikely(!ret)) {
		tcp_conn_destroy(c);
		return ret;
	}

	*c_out = c;
	return 0;
}

/**
 * tcp_local_addr - gets the local address of a TCP connection
 * @c: the TCP connection
 */
struct netaddr tcp_local_addr(tcpconn_t *c)
{
	return c->e.laddr;
}

/**
 * tcp_remote_addr - gets the remote address of a TCP connection
 * @c: the TCP connection
 */
struct netaddr tcp_remote_addr(tcpconn_t *c)
{
	return c->e.raddr;
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
