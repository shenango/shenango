/*
 * tcp_out.c - the egress datapath for TCP
 */

#include <string.h>

#include <base/stddef.h>
#include <net/ip.h>
#include <net/tcp.h>

#include "tcp.h"
#include "defs.h"

static struct tcp_hdr *
tcp_push_tcphdr(struct mbuf *m, tcpconn_t *c, uint8_t flags)
{
	struct tcp_hdr *tcphdr;
	tcp_seq ack = c->tx_last_ack = load_acquire(&c->pcb.rcv_nxt);
	uint16_t win = c->tx_last_win = load_acquire(&c->pcb.rcv_wnd);

	/* write the tcp header */
	tcphdr = mbuf_push_hdr(m, *tcphdr);
	tcphdr->sport = hton16(c->e.laddr.port);
	tcphdr->dport = hton16(c->e.raddr.port);
	tcphdr->ack = hton32(ack);
	tcphdr->off = 5;
	tcphdr->flags = flags;
	tcphdr->win = hton16(win);
	return tcphdr;
}

/**
 * tcp_tx_raw_rst - send a reset without an established connection
 * @laddr: the local address
 * @raddr: the remote address
 * @seq: the TCP sequence number
 *
 * Returns 0 if successful, otherwise fail.
 */
int tcp_tx_raw_rst(struct netaddr laddr, struct netaddr raddr, tcp_seq seq)
{
	struct tcp_hdr *tcphdr;
	struct mbuf *m;
	int ret;

	m = net_tx_alloc_mbuf();
	if (unlikely((!m)))
		return -ENOMEM;

	/* write the tcp header */
	tcphdr = mbuf_push_hdr(m, *tcphdr);
	tcphdr->sport = hton16(laddr.port);
	tcphdr->dport = hton16(raddr.port);
	tcphdr->seq = hton32(seq);
	tcphdr->ack = hton32(0);
	tcphdr->off = 5;
	tcphdr->flags = TCP_RST;
	tcphdr->win = hton16(0);

	/* transmit packet */
	ret = net_tx_ip(m, IPPROTO_TCP, raddr.ip);
	if (unlikely(ret))
		mbuf_free(m);
	return ret;
}

/**
 * tcp_tx_ctl - sends a control message without data
 * @c: the TCP connection
 * @flags: the control flags (e.g. TCP_ACK, etc.)
 * @retransmit: should the control message be retransmitted?
 *
 * Returns 0 if successful, -ENOMEM if out memory, and -EAGAIN if another
 * thread has transmit exclusive rights on the connection.
 */
int tcp_tx_ctl(tcpconn_t *c, uint8_t flags, bool retransmit)
{
	struct tcp_hdr *tcphdr;
	struct mbuf *m;
	int ret;

	m = net_tx_alloc_mbuf();
	if (unlikely(!m))
		return -ENOMEM;

	kref_initn(&m->ref, retransmit ? 2 : 1);
	tcphdr = tcp_push_tcphdr(m, c, flags);

	spin_lock_np(&c->lock);
	assert(!c->tx_pending);
	if (c->tx_exclusive) {
		spin_unlock_np(&c->lock);
		mbuf_free(m);
		return -EAGAIN;
	}
	m->seg = c->pcb.snd_nxt;
	tcphdr->seq = hton32(c->pcb.snd_nxt);
	if (retransmit) {
		c->pcb.snd_nxt++;
		mbufq_push_tail(&c->txq, m);
	}
	spin_unlock_np(&c->lock);

	m->timestamp = microtime();
	ret = net_tx_ip(m, IPPROTO_TCP, c->e.raddr.ip);
	if (unlikely(ret))
		mbuf_rput(m);
	return ret;
}

/**
 * tcp_tx_buf - transmit a buffer on a TCP connection
 * @c: the TCP connection
 * @buf: the buffer to transmit
 * @len: the length of the buffer to transmit
 * @push: indicates the data is ready for consumption by the receiver
 *
 * If @push is false, the implementation may buffer some or all of the data for
 * future transmission. tcp_tx_buf() must be called with @push equal to true
 * before dropping TX exclusive on the socket.
 *
 * WARNING: The caller is responsible for respecting the TCP window size limit.
 *
 * Returns the number of bytes transmitted, or < 0 if there was an error.
 */
ssize_t tcp_tx_buf(tcpconn_t *c, const void *buf, size_t len, bool push)
{
	struct tcp_hdr *tcphdr;
	struct mbuf *m;
	const char *pos = buf;
	const char *end = pos + len;
	ssize_t ret = 0;
	size_t seglen;

	assert(c->pcb.state == TCP_STATE_SYN_SENT ||
	       c->pcb.state == TCP_STATE_SYN_RECEIVED ||
	       c->pcb.state == TCP_STATE_ESTABLISHED);
	assert(c->tx_exclusive);

	pos = buf;
	end = pos + len;

	/* the main TCP segmenter loop */
	while (pos < end) {
		/* allocate a buffer and copy payload data */
		if (c->tx_pending) {
			m = c->tx_pending;
			c->tx_pending = NULL;
			seglen = min(end - pos, TCP_MSS - mbuf_length(m) +
				     sizeof(struct tcp_hdr));
		} else {
			uint8_t flags = TCP_ACK;

			m = net_tx_alloc_mbuf();
			if (unlikely(!m)) {
				ret = -ENOBUFS;
				break;
			}
			seglen = min(end - pos, TCP_MSS);
			kref_init(&m->ref);
			m->seg = c->pcb.snd_nxt;

			/* initialize TCP header */
			if (push && pos + seglen == end)
				flags |= TCP_PUSH;
			tcphdr = tcp_push_tcphdr(m, c, flags);
			tcphdr->seq = hton32(c->pcb.snd_nxt);
		}

		c->pcb.snd_nxt += seglen;
		memcpy(mbuf_put(m, seglen), pos, seglen);
		pos += seglen;

		/* if not pushing, keep the last buffer for later */
		if (!push && pos == end && mbuf_length(m) -
		    sizeof(struct tcp_hdr) < TCP_MSS) {
			c->tx_pending = m;
			break;
		}
		mbufq_push_tail(&c->txq, m);

		/* transmit the packet if connection is established */
		if (c->pcb.state != TCP_STATE_ESTABLISHED)
			continue;
		mbuf_rget(m);
		m->timestamp = microtime();
		ret = net_tx_ip(m, IPPROTO_TCP, c->e.raddr.ip);
		if (unlikely(ret))
			mbuf_rput(m);
	}

	/* if we sent anything return the length we sent instead of an error */
	if (pos - (const char *)buf > 0)
		ret = pos - (const char *)buf;
	return ret;
}
