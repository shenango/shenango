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

/**
 * tcp_conn_ack - removes acknowledged packets from TX queue
 * @c: the TCP connection to update
 * @freeq: a pointer to a list to store acknowledged buffers to later free
 *
 * WARNING: the caller must hold @c->lock.
 * @freeq is provided so that @c->lock can be released before freeing buffers.
 */
void tcp_conn_ack(tcpconn_t *c, struct list_head *freeq)
{
	struct mbuf *m;

	assert_spin_lock_held(&c->lock);

	/* will free these segments later */
	if (c->tx_exclusive)
		return;

	/* dequeue buffers that are fully acknowledged */
	while (true) {
		m = list_top(&c->txq, struct mbuf, link);
		if (!m)
			break;
		if (wraps_gt(m->seg_end, c->pcb.snd_una))
			break;

		list_pop(&c->txq, struct mbuf, link);
		list_add_tail(freeq, &m->link);
	}
}

/**
 * tcp_conn_set_state - changes the TCP PCB state
 * @c: the TCP connection to update
 * @new_state: the new TCP_STATE_* value
 *
 * WARNING: @c->lock must be held by the caller.
 * WARNING: @new_state must be greater than the current state.
 */
void tcp_conn_set_state(tcpconn_t *c, int new_state)
{
	assert_spin_lock_held(&c->lock);
	assert(c->pcb.state == TCP_STATE_CLOSED || c->pcb.state < new_state);

	/* unblock any threads waiting for the connection to be established */
	if (c->pcb.state < TCP_STATE_ESTABLISHED &&
	    new_state >= TCP_STATE_ESTABLISHED) {
		waitq_release(&c->rx_wq);
		waitq_release(&c->tx_wq);
	}

	tcp_debug_state_change(c, c->pcb.state, new_state);
	c->pcb.state = new_state;
}

/* handles network errors for TCP sockets */
static void tcp_conn_err(struct trans_entry *e, int err)
{
	tcpconn_t *c = container_of(e, tcpconn_t, e);

	spin_lock_np(&c->lock);
	tcp_conn_fail(c, err);
	spin_unlock_np(&c->lock);
}

/* operations for TCP sockets */
const struct trans_ops tcp_conn_ops = {
	.recv = tcp_rx_conn,
	.err = tcp_conn_err,
};


/*
 * Connection initialization
 */

/**
 * tcp_conn_alloc - allocates a TCP connection struct
 *
 * Returns a connection, or NULL if out of memory.
 */
tcpconn_t *tcp_conn_alloc(void)
{
	tcpconn_t *c;

	c = smalloc(sizeof(*c));
	if (!c)
		return NULL;

	/* general fields */
	memset(&c->pcb, 0, sizeof(c->pcb));
	spin_lock_init(&c->lock);
	kref_init(&c->ref);
	c->err = 0;

	/* ingress fields */
	c->rx_closed = false;
	c->rx_exclusive = false;
	waitq_init(&c->rx_wq);
	list_head_init(&c->rxq_ooo);
	list_head_init(&c->rxq);

	/* egress fields */
	c->tx_closed = false;
	c->tx_exclusive = false;
	waitq_init(&c->tx_wq);
	c->tx_last_ack = 0;
	c->tx_last_win = 0;
	c->tx_pending = NULL;
	list_head_init(&c->txq);

	/* initialize egress half of PCB */
	c->pcb.state = TCP_STATE_CLOSED;
	c->pcb.iss = microtime(); /* TODO: not secure */
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

	if (c->tx_pending)
		mbuf_free(c->tx_pending);
	mbuf_list_free(&c->rxq_ooo);
	mbuf_list_free(&c->rxq);
	mbuf_list_free(&c->txq);
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

/**
 * tcp_conn_release_ref - a helper to free the conn when ref reaches zero
 * @r: the embedded reference count structure
 */
void tcp_conn_release_ref(struct kref *r)
{
	tcpconn_t *c = container_of(r, tcpconn_t, ref);

	tcp_conn_destroy(c);
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
	tcpconn_t *c;
	thread_t *th;

	/* make sure the connection queue isn't full */
	spin_lock_np(&q->l);
	if (unlikely(q->backlog == 0 || q->shutdown)) {
		spin_unlock_np(&q->l);
		goto done;
	}
	q->backlog--;
	spin_unlock_np(&q->l);

	/* create a new connection */
	c = tcp_rx_listener(e->laddr, m);
	if (!c) {
		spin_lock_np(&q->l);
		q->backlog++;
		spin_unlock_np(&q->l);
		goto done;
	}

	/* wake a thread to accept the connection */
	spin_lock_np(&q->l);
	list_add_tail(&q->conns, &c->link);
	th = waitq_signal(&q->wq, &q->l);
	spin_unlock_np(&q->l);
	waitq_signal_finish(th);

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
	c = tcp_conn_alloc();
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

	/* send a SYN to the remote host */
	spin_lock_np(&c->lock);
	ret = tcp_tx_ctl(c, TCP_SYN);
	if (unlikely(!ret)) {
		spin_unlock_np(&c->lock);
		tcp_conn_destroy(c);
		return ret;
	}
	tcp_conn_get(c); /* take a ref for the state machine */
	tcp_conn_set_state(c, TCP_STATE_SYN_SENT);

	/* wait until the connection is established or there is a failure */
	while (!c->rx_closed && c->pcb.state < TCP_STATE_ESTABLISHED)
		waitq_wait(&c->tx_wq, &c->lock);

	/* check if the connection failed */
	if (c->rx_closed) {
		ret = -c->err;
		spin_unlock_np(&c->lock);
		tcp_conn_destroy(c);
		return ret;
	}
	spin_unlock_np(&c->lock);

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

static ssize_t tcp_read_wait(tcpconn_t *c, size_t len,
			     struct list_head *q, struct mbuf **mout)
{
	struct mbuf *m;
	size_t readlen = 0;

	*mout = NULL;
	spin_lock_np(&c->lock);

	/* block until there is an actionable event */
	while (!c->rx_closed &&
	       (c->pcb.state < TCP_STATE_ESTABLISHED || c->rx_exclusive ||
		list_empty(&c->rxq))) {
		waitq_wait(&c->rx_wq, &c->lock);
	}

	/* is the socket closed? */
	if (c->rx_closed && list_empty(&c->rxq)) {
		spin_unlock_np(&c->lock);
		return -c->err;
	}

	/* pop off the mbufs that will be read */
	while (readlen < len) {
		m = list_pop(&c->rxq, struct mbuf, link);
		if (!m)
			break;

		if (len - readlen < mbuf_length(m)) {
			c->rx_exclusive = true;
			*mout = m;
			readlen = len;
			break;
		}

		list_add_tail(q, &m->link);
		readlen += mbuf_length(m);
	}

	spin_unlock_np(&c->lock);
	return readlen;
}

static void tcp_read_finish(tcpconn_t *c, struct mbuf *m, size_t len)
{
	thread_t *th;

	if (!m)
		return;

	spin_lock_np(&c->lock);
	c->pcb.rcv_wnd += len;
	c->rx_exclusive = false;
	th = waitq_signal(&c->rx_wq, &c->lock);
	spin_unlock_np(&c->lock);
	waitq_signal_finish(th);
}

/**
 * tcp_read - reads data from a TCP connection
 * @c: the TCP connection
 * @buf: a buffer to store the read data
 * @len: the length of @buf
 *
 * Returns the number of bytes read, 0 if the connection is closed, or < 0
 * if an error occurred.
 */
ssize_t tcp_read(tcpconn_t *c, void *buf, size_t len)
{
	char *pos = buf;
	struct list_head q;
	struct mbuf *m;
	ssize_t ret;

	list_head_init(&q);

	/* wait for data to become available */
	ret = tcp_read_wait(c, len, &q, &m);

	/* check if connection was closed */
	if (ret <= 0)
		return ret;

	/* copy the data from the buffers */
	while (true) {
		struct mbuf *cur = list_pop(&q, struct mbuf, link);
		if (!cur)
			break;

		memcpy(pos, mbuf_data(cur), mbuf_length(cur));
		pos += mbuf_length(cur);
		mbuf_free(cur);
	}

	/* we may have to consume only part of a buffer */
	if (m) {
		size_t cpylen = len - (uintptr_t)pos + (uintptr_t)buf;
		memcpy(pos, mbuf_pull(m, cpylen), cpylen);
		m->seg_seq += cpylen;
	}

	/* wakeup any pending readers */
	tcp_read_finish(c, m, ret);

	return ret;
}

static size_t iov_len(const struct iovec *iov, int iovcnt)
{
	size_t len = 0;
	int i;

	for (i = 0; i < iovcnt; i++)
		len += iov[iovcnt].iov_len;

	return len;
}

/**
 * tcp_readv - reads vectored data from a TCP connection
 * @c: the TCP connection
 * @iov: a pointer to the IO vector
 * @iovcnt: the number of vectors in @iov
 *
 * Returns the number of bytes read, 0 if the connection is closed, or < 0
 * if an error occurred.
 */
ssize_t tcp_readv(tcpconn_t *c, const struct iovec *iov, int iovcnt)
{
	struct list_head q;
	struct mbuf *m;
	ssize_t len = iov_len(iov, iovcnt);
	off_t offset = 0;
	int i = 0;

	list_head_init(&q);

	/* wait for data to become available */
	len = tcp_read_wait(c, len, &q, &m);

	/* check if connection was closed */
	if (len <= 0)
		return len;

	/* copy the data from the buffers */
	while (true) {
		struct mbuf *cur = list_pop(&q, struct mbuf, link);
		if (!cur)
			break;

		do {
			const struct iovec *vp = &iov[i];
			size_t cpylen = min(vp->iov_len - offset,
					    mbuf_length(m));

			memcpy((char *)vp->iov_base + offset,
			       mbuf_pull(m, cpylen), cpylen);

			offset += cpylen;
			if (offset == vp->iov_len) {
				offset = 0;
				i++;
			}

			assert(i <= iovcnt);
		} while (mbuf_length(m) > 0);
		mbuf_free(cur);
	}

	/* we may have to consume only part of a buffer */
	if (m) {
		do {
			const struct iovec *vp = &iov[i];
			size_t cpylen = min(vp->iov_len - offset,
					    mbuf_length(m));

			memcpy((char *)vp->iov_base + offset,
			       mbuf_pull(m, cpylen), cpylen);
			m->seg_seq += cpylen;
			offset += cpylen;
			if (offset == vp->iov_len) {
				offset = 0;
				i++;
			}

			assert(mbuf_length(m) > 0);
		} while (i < iovcnt);
	}

	/* wakeup any pending readers */
	tcp_read_finish(c, m, len);

	return len;
}

static int tcp_write_wait(tcpconn_t *c, size_t *winlen)
{
	spin_lock_np(&c->lock);

	/* block until there is an actionable event */
	while (!c->tx_closed &&
	       (c->pcb.state < TCP_STATE_ESTABLISHED || c->tx_exclusive ||
		(c->pcb.snd_una + c->pcb.snd_wnd <= c->pcb.snd_nxt &&
		 !list_empty(&c->txq)))) {
		waitq_wait(&c->tx_wq, &c->lock);
	}

	/* is the socket closed? */
	if (c->tx_closed) {
		spin_unlock_np(&c->lock);
		return c->err ? -c->err : -EPIPE;
	}

	/* drop the lock to allow concurrent RX processing */
	c->tx_exclusive = true;
	/* must allow at least one byte to avoid zero window deadlock */
	*winlen = max(c->pcb.snd_una + c->pcb.snd_wnd - c->pcb.snd_nxt, 1);
	spin_unlock_np(&c->lock);

	return 0;
}

static void tcp_write_finish(tcpconn_t *c)
{
	struct list_head q;
	thread_t *th;

	assert(c->tx_exclusive == true);
	list_head_init(&q);

	spin_lock_np(&c->lock);
	c->tx_exclusive = false;
	tcp_conn_ack(c, &q);
	if (c->pcb.rcv_nxt != c->tx_last_ack)
		tcp_tx_ack(c);
	th = waitq_signal(&c->tx_wq, &c->lock);
	spin_unlock_np(&c->lock);

	waitq_signal_finish(th);
	mbuf_list_free(&q);
}

/**
 * tcp_write - writes data to a TCP connection
 * @c: the TCP connection
 * @buf: a buffer from which to copy the data
 * @len: the length of the data
 *
 * Returns the number of bytes written (could be less than @len), or < 0
 * if there was a failure.
 */
ssize_t tcp_write(tcpconn_t *c, const void *buf, size_t len)
{
	size_t winlen;
	ssize_t ret;

	/* block until the data can be sent */
	ret = tcp_write_wait(c, &winlen);
	if (ret)
		return ret;

	/* actually send the data */
	ret = tcp_tx_buf(c, buf, min(len, winlen), len <= winlen);

	/* catch up on any pending work */
	tcp_write_finish(c);

	return ret;
}

/**
 * tcp_writev - writes vectored data to a TCP connection
 * @c: the TCP connection
 * @iov: a pointer to the IO vector
 * @iovcnt: the number of vectors in @iov
 *
 * Returns the number of bytes written (could be less than requested), or < 0
 * if there was a failure.
 */
ssize_t tcp_writev(tcpconn_t *c, const struct iovec *iov, int iovcnt)
{
	size_t winlen;
	ssize_t sent = 0, ret;
	int i;

	/* block until the data can be sent */
	ret = tcp_write_wait(c, &winlen);
	if (ret)
		return ret;

	/* actually send the data */
	for (i = 0; i < iovcnt; i++) {
		if (winlen <= 0)
			break;
		ret = tcp_tx_buf(c, iov->iov_base, min(iov->iov_len, winlen),
				 i == iovcnt - 1 && iov->iov_len <= winlen);
		if (ret <= 0)
			break;
		winlen -= ret;
		sent += ret;
	}

	/* catch up on any pending work */
	tcp_write_finish(c);

	return sent > 0 ? sent : ret;
}

/**
 * tcp_conn_fail - closes a TCP both sides of a connection with an error
 * @c: the TCP connection to shutdown
 * @err: the error code (failure reason for the close)
 *
 * The caller must hold @c's lock.
 */
void tcp_conn_fail(tcpconn_t *c, int err)
{
	assert_spin_lock_held(&c->lock);

	c->err = err;
	tcp_conn_set_state(c, TCP_STATE_CLOSED);

	if (!c->rx_closed) {
		c->rx_closed = true;
		waitq_release(&c->rx_wq);
	}

	if (!c->tx_closed) {
		c->tx_closed = true;
		waitq_release(&c->tx_wq);
	}

	/* state machine is disabled, drop ref */
	tcp_conn_put(c);
}

/**
 * tcp_conn_shutdown_rx - closes ingress for a TCP connection
 * @c: the TCP connection to shutdown
 *
 * The caller must hold @c's lock.
 */
void tcp_conn_shutdown_rx(tcpconn_t *c)
{
	assert_spin_lock_held(&c->lock);

	if (c->rx_closed)
		return;

	c->rx_closed = true;
	waitq_release(&c->rx_wq);
}

static int tcp_conn_shutdown_tx(tcpconn_t *c)
{
	int ret;

	assert_spin_lock_held(&c->lock);

	if (c->tx_closed)
		return 0;

	assert(c->pcb.state >= TCP_STATE_ESTABLISHED);
	while (c->tx_exclusive)
		waitq_wait(&c->tx_wq, &c->lock);
	ret = tcp_tx_ctl(c, TCP_FIN | TCP_ACK);
	if (unlikely(ret))
		return ret;
	if (c->pcb.state == TCP_STATE_ESTABLISHED)
		tcp_conn_set_state(c, TCP_STATE_FIN_WAIT1);
	else if (c->pcb.state == TCP_STATE_CLOSE_WAIT)
		tcp_conn_set_state(c, TCP_STATE_LAST_ACK);
	else
		WARN();

	c->tx_closed = true;
	waitq_release(&c->tx_wq);

	return 0;
}

/**
 * tcp_shutdown - shuts a TCP connection down
 * @c: the TCP connection to shutdown
 * @how: the directions to shutdown (SHUT_RD, SHUT_WR, or SHUT_RDWR)
 *
 * Returns 0 if successful, otherwise < 0 for failure.
 */
int tcp_shutdown(tcpconn_t *c, int how)
{
	bool tx, rx;
	int ret;

	if (how != SHUT_RD && how != SHUT_WR && how != SHUT_RDWR)
		return -EINVAL;

	tx = how == SHUT_WR || how == SHUT_RDWR;
	rx = how == SHUT_RD || how == SHUT_RDWR;

	spin_lock_np(&c->lock);
	if (tx) {
		ret = tcp_conn_shutdown_tx(c);
		if (ret) {
			spin_unlock_np(&c->lock);
			return ret;
		}
	}
	if (rx)
		tcp_conn_shutdown_rx(c);
	spin_unlock_np(&c->lock);

	return 0;
}

/**
 * tcp_abort - force an immediate close (graceful) of the connection
 * @c: the TCP connection to abort
 */
void tcp_abort(tcpconn_t *c)
{
	spin_lock_np(&c->lock);
	if (c->pcb.state == TCP_STATE_CLOSED) {
		spin_unlock_np(&c->lock);
		return;
	}
	tcp_tx_raw_rst(c->e.laddr, c->e.raddr, c->pcb.snd_nxt);
	tcp_conn_fail(c, ECONNABORTED);
	spin_unlock_np(&c->lock);
}

/**
 * tcp_close - frees a TCP connection
 * @c: the TCP connection to free
 *
 * WARNING: Only the last reference can safely call this method. Call
 * tcp_shutdown() first if any threads are sleeping on the socket.
 */
void tcp_close(tcpconn_t *c)
{
	int ret;

	spin_lock_np(&c->lock);
	BUG_ON(!waitq_empty(&c->tx_wq));
	BUG_ON(!waitq_empty(&c->rx_wq));
	ret = tcp_conn_shutdown_tx(c);
	if (ret)
		tcp_conn_fail(c, -ret);
	tcp_conn_shutdown_rx(c);
	spin_unlock_np(&c->lock);
	tcp_conn_put(c);
}
