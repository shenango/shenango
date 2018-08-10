/*
 * tcp.h - local header for TCP support
 */

#include <base/stddef.h>
#include <base/list.h>
#include <runtime/sync.h>
#include <runtime/tcp.h>
#include <net/tcp.h>
#include <net/mbuf.h>
#include <net/mbufq.h>

#include "defs.h"
#include "waitq.h"

#define TCP_MSS	(ETH_MTU - sizeof(struct ip_hdr) - sizeof(struct tcp_hdr))
#define TCP_WIN	((32768 / TCP_MSS) * TCP_MSS)

/* connecion states (RFC 793 Section 3.2) */
enum {
	TCP_STATE_SYN_SENT = 0,
	TCP_STATE_SYN_RECEIVED,
	TCP_STATE_ESTABLISHED,
	TCP_STATE_FIN_WAIT1,
	TCP_STATE_FIN_WAIT2,
	TCP_STATE_CLOSE_WAIT,
	TCP_STATE_CLOSING,
	TCP_STATE_LAST_ACK,
	TCP_STATE_TIME_WAIT,
	TCP_STATE_CLOSED,
};

/* TCP protocol control block (PCB) */
struct tcp_pcb {
	int		state;		/* the connection state */

	/* send sequence variables (RFC 793 Section 3.2) */
	uint32_t	snd_una;	/* send unacknowledged */
	uint32_t	snd_nxt;	/* send next */
	uint32_t	snd_wnd;	/* send window */
	uint32_t	snd_up;		/* send urgent pointer */
	uint32_t	snd_wl1;	/* last window update - seq number */
	uint32_t	snd_wl2;	/* last window update - ack number */
	uint32_t	iss;		/* initial send sequence number */

	/* receive sequence variables (RFC 793 Section 3.2) */
	uint32_t	rcv_nxt;	/* receive next */
	uint32_t	rcv_wnd;	/* receive window */
	uint32_t	rcv_up;		/* receive urgent pointer */
	uint32_t	irs;		/* initial receive sequence number */
};

/* the TCP connection struct */
struct tcpconn {
	struct trans_entry	e;
	struct tcp_pcb		pcb;
	struct list_node	link;
	spinlock_t		lock;
	int			err; /* error code for read(), write(), etc. */

	/* ingress path */
	unsigned int		rx_closed:1;
	unsigned int		rx_exclusive:1;
	waitq_t			rx_wq;
	struct mbufq		rxq_ooo;
	struct mbufq		rxq;

	/* egress path */
	unsigned int		tx_closed:1;
	unsigned int		tx_exclusive:1;
	waitq_t			tx_wq;
	uint32_t		tx_last_ack;
	uint16_t		tx_last_win;
	struct mbuf		*tx_pending;
	struct mbufq		txq;
};

extern tcpconn_t *tcp_conn_alloc();
extern int tcp_conn_attach(tcpconn_t *c, struct netaddr laddr,
			   struct netaddr raddr);
extern void tcp_conn_destroy(tcpconn_t *c);
extern void tcp_conn_fail(tcpconn_t *c, int err);


/*
 * ingress path
 */

extern void tcp_rx_conn(struct trans_entry *e, struct mbuf *m);
extern tcpconn_t *tcp_rx_listener(struct netaddr laddr, struct mbuf *m);


/*
 * egress path
 */

extern int tcp_tx_raw_rst(struct netaddr laddr, struct netaddr raddr,
			  tcp_seq seq);
extern int tcp_tx_raw_rst_ack(struct netaddr laddr, struct netaddr raddr,
			      tcp_seq seq, tcp_seq ack);
extern int tcp_tx_ack(tcpconn_t *c);
extern int tcp_tx_ctl(tcpconn_t *c, uint8_t flags);
extern ssize_t tcp_tx_buf(tcpconn_t *c, const void *buf, size_t len, bool push);
