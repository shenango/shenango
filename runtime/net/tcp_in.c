/*
 * tcp_in.c - the ingress datapath for TCP
 */

#include <base/stddef.h>
#include <runtime/smalloc.h>
#include <net/ip.h>
#include <net/tcp.h>

#include "tcp.h"
#include "defs.h"

/* handles ingress packets for TCP connections */
void tcp_rx_conn(struct trans_entry *e, struct mbuf *m)
{

}

/* handles ingress packets for TCP listener queues */
tcpconn_t *tcp_rx_listener(struct netaddr laddr, struct mbuf *m)
{
	struct netaddr raddr;
	const struct ip_hdr *iphdr;
	const struct tcp_hdr *tcphdr;
	tcpconn_t *c;
	int ret;

	/* find header offsets */
	iphdr = mbuf_network_hdr(m, *iphdr);
	tcphdr = mbuf_pull_hdr_or_null(m, *tcphdr);
	if (unlikely(!tcphdr))
		return NULL;

	/* calculate local and remote network addresses */
	raddr.ip = ntoh32(iphdr->saddr);
	raddr.port = ntoh16(tcphdr->sport);

	/* do exactly what RFC 793 says */
	if ((tcphdr->flags & TCP_RST) > 0)
		return NULL;
	if ((tcphdr->flags & TCP_ACK) > 0) {
		tcp_tx_raw_rst(laddr, raddr, ntoh32(tcphdr->ack));
		return NULL;
	}
	if ((tcphdr->flags & TCP_SYN) == 0)
		return NULL;

	/* TODO: the spec requires us to enqueue but not post any data */
	if (ntoh16(iphdr->len) - sizeof(*iphdr) != sizeof(*tcphdr))
		return NULL;

	/* we have a valid SYN packet, initialize a new connection */
	c = tcp_conn_alloc(TCP_STATE_SYN_RECEIVED);
	if (unlikely(!c))
		return NULL;
	c->pcb.irs = ntoh32(tcphdr->seq);
	c->pcb.rcv_nxt = c->pcb.irs + 1;

	/*
	 * Attach the connection to the transport layer. From this point onward
	 * ingress packets can be dispatched to the connection.
	 */
	ret = tcp_conn_attach(c, laddr, raddr);
	if (unlikely(!ret)) {
		sfree(c);
		return NULL;
	}

	/* finally, send a SYN/ACK to the remote host */
	ret = tcp_tx_ctl(c, TCP_SYN | TCP_ACK, true);
	if (unlikely(!ret)) {
		tcp_conn_destroy(c);
		return NULL;
	}

	return c;
}
