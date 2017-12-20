/*
 * ip.c - support for Internet Protocol version 4 (IPv4)
 */

#include <stdlib.h>

#include <net/ip.h>

#include "defs.h"

/**
 * net_tx_ip - transmits an IP packet
 * @m: the mbuf to transmit
 * @daddr: the destination IP address (in native byte order)
 *
 * The payload must start with the transport (L4) header. The IPv4 and ethernet
 * headers will be prepended by this function.
 *
 * Returns 0 if successful. If successful, the mbuf will be freed when the
 * the transmit completes. Otherwise, the mbuf still belongs to the caller.
 */
int net_tx_ip(struct mbuf *m, uint8_t proto, uint32_t daddr)
{
	int ret;
	struct ip_hdr *iphdr;

	/* populate IP header */
	iphdr = mbuf_push_hdr(m, *iphdr);
	iphdr->version = IPVERSION;
	iphdr->header_len = 5;
	iphdr->tos = IPTOS_DSCP_CS0 | IPTOS_ECN_NOTECT;
	iphdr->len = hton16(mbuf_length(m));
	/* TODO: there are some uniqueness requirements on the ID, see RFC 6864 */
	iphdr->id = rand() % 65536;
	iphdr->off = 0;
	iphdr->ttl = 64;
	iphdr->proto = proto;
	iphdr->chksum = 0;
	iphdr->saddr = hton32(netcfg.addr);
	iphdr->daddr = hton32(daddr);

	m->txflags |= OLFLAG_IP_CHKSUM | OLFLAG_IPV4;
	ret = net_tx_xmit_to_ip(m, daddr);
	if (unlikely(ret))
		mbuf_pull_hdr(m, *iphdr);
	return ret;
}
