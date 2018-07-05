/*
 * tcp.h - TCP sockets
 */

#pragma once

#include <runtime/net.h>
#include <sys/uio.h>

struct tcpqueue;
typedef struct tcpqueue tcpqueue_t;
struct tcpconn;
typedef struct tcpconn tcpconn_t;

extern int tcp_dial(struct netaddr laddr, struct netaddr raddr,
		    tcpconn_t **c_out);
extern int tcp_listen(struct netaddr laddr, tcpqueue_t **q_out);
extern int tcp_accept(tcpqueue_t *q, tcpconn_t *c);
extern int tcp_qclose(tcpqueue_t *q);
extern struct netaddr tcp_local_addr(tcpconn_t *c);
extern struct netaddr tcp_remote_addr(tcpconn_t *c);
extern int tcp_set_buffers(tcpconn_t *c, size_t read_len, size_t write_len);
extern ssize_t tcp_read(udpconn_t *c, void *buf, size_t len);
extern ssize_t tcp_write(udpconn_t *c, const void *buf, size_t len);
extern ssize_t tcp_readv(const struct iovec *iov, int iovcnt);
extern ssize_t tcp_writev(const struct iovec *iov, int iovcnt);
extern void tcp_shutdown(udpconn_t *c, int how);
extern void tcp_close(udpconn_t *c);
