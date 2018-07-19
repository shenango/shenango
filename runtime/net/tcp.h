/*
 * tcp.h - local header for TCP support
 */

#include <runtime/sync.h>
#include <net/tcp.h>

/* connecion states (RFC 793 Section 3.2) */
enum {
	TCP_STATE_LISTEN = 0,
	TCP_STATE_SYN_SENT,
	TCP_STATE_SYN_RECEIVED,
	TCP_STATE_ESTABLISHED,
	TCP_STATE_FIN_WAIT1,
	TCP_STATE_FIN_WAIT2,
	TCP_STATE_CLOSE_WAIT,
	TCP_STATE_CLOSING,
	TCP_STATE_LAST_ACK,
	TCP_STATE_TIME_WAIT,
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
