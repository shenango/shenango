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
	int			inq_er;
	struct list_head	inq_waiters;
	struct mbufq		inq;

	/* egress queue */
	size_t			outq_cap;
	size_t			outq_len;
	struct list_head	outq_waiters;
};

static void tcp_conn_init(tcpconn_t *c)
{
	spin_lock_init(&c->lock);
}


/*
 * Support for ingress TCP handling
 */

/* handles ingress packets for TCP sockets */
static void tcp_recv(struct trans_entry *e, struct mbuf *m)
{

}


/*
 * Support for accepting new connections
 */

struct tcpqueue {
	struct trans_entry	e;
	struct kref		ref;

	mutex_t			m;
	condvar_t		cv;
	struct list_head	conns;
};

int tcp_listen(struct netaddr laddr, tcpqueue_t **q_out)
{
	return -ENOTSUP;
}

int tcp_accept(tcpqueue_t *q, tcpconn_t **c_out)
{
	return -ENOTSUP;
}

int tcp_qclose(tcpqueue_t *q)
{
	return -ENOTSUP;
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
