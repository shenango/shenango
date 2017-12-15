/*
 * icmp.c - support for Internet Control Message Protocol (ICMP)
 */

#include <string.h>

#include <asm/chksum.h>
#include <base/log.h>
#include <net/icmp.h>

#include "defs.h"

static void net_rx_icmp_echo(struct icmp_hdr *in_icmp_hdr,
			     struct ip_hdr *in_iphdr, uint16_t len)
{
	struct mbuf *outgoing;
	struct ip_hdr *out_iphdr;
	struct icmp_hdr *out_icmp_hdr;
	struct ip_addr dst_ip_addr;

	log_debug("icmp: responding to icmp echo request");

	outgoing = net_tx_alloc_mbuf();
	if (unlikely(!outgoing))
		return;

	/* copy incoming IP hdr, swap addrs */
	out_iphdr = (struct ip_hdr *)mbuf_put(outgoing,
			in_iphdr->header_len * sizeof(uint32_t));
	memcpy(out_iphdr, in_iphdr, in_iphdr->header_len * sizeof(uint32_t));
	out_iphdr->src_addr = in_iphdr->dst_addr;
	out_iphdr->dst_addr = in_iphdr->src_addr;
	out_iphdr->chksum = 0;

	/* copy incoming ICMP hdr and data, set type and checksum */
	out_icmp_hdr = (struct icmp_hdr *)mbuf_put(outgoing, len);
	memcpy(out_icmp_hdr, in_icmp_hdr, len);
	out_icmp_hdr->type = ICMP_ECHOREPLY;
	out_icmp_hdr->chksum = 0;
	out_icmp_hdr->chksum = chksum_internet((char *) out_icmp_hdr, len);

	outgoing->txflags |= OLFLAG_IP_CHKSUM | OLFLAG_IPV4;
	dst_ip_addr.addr = ntoh32(out_iphdr->dst_addr.addr);

	if (unlikely(net_tx_xmit_to_ip(outgoing, dst_ip_addr)))
		mbuf_free(outgoing);
}

void net_rx_icmp(struct mbuf *m, struct ip_hdr *iphdr, uint16_t len)
{
	struct icmp_hdr *icmp_hdr;

	icmp_hdr = (struct icmp_hdr *)mbuf_pull_or_null(m,
			sizeof(struct icmp_hdr));
	if (unlikely(!icmp_hdr))
		goto drop;

	switch (icmp_hdr->type) {
	case ICMP_ECHO:
		net_rx_icmp_echo(icmp_hdr, iphdr, len);
		break;
	default:
		log_err("icmp: type %d not yet supported", icmp_hdr->type);
		break;
	}

drop:
	mbuf_free(m);
}
