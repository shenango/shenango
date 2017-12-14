/*
 * udp.c - support for User Datagram Protocol (UDP)
 */

#include "defs.h"

#include <net/udp.h>

void dump_udp_pkt(int loglvl, struct ip_addr *src, struct udp_hdr *udp_hdr,
          void *data);

void net_rx_udp(struct mbuf *m, struct ip_addr *src, uint16_t len)
{
	struct udp_hdr *hdr;

	hdr = mbuf_pull_hdr_or_null(m, *hdr);
	if (unlikely(!hdr))
		goto drop;

	if (unlikely(ntoh16(hdr->len) != len))
		goto drop;


	dump_udp_pkt(0, src, hdr, mbuf_data(m));

	// return;

drop:
	mbuf_free(m);
}
