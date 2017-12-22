/*
 * icmp.c - support for Internet Control Message Protocol (ICMP)
 */

#include <string.h>

#include <asm/chksum.h>
#include <base/compiler.h>
#include <base/log.h>
#include <net/icmp.h>

#include "defs.h"

static void net_rx_icmp_echo(const struct icmp_hdr *in_icmp_hdr,
		const struct ip_hdr *in_iphdr, uint16_t len)
{
	struct mbuf *m;
	struct icmp_hdr *out_icmp_hdr;

	log_debug("icmp: responding to icmp echo request");

	m = net_tx_alloc_mbuf();
	if (unlikely(!m))
		return;

	/* copy incoming ICMP hdr and data, set type and checksum */
	out_icmp_hdr = (struct icmp_hdr *)mbuf_put(m, len);
	memcpy(out_icmp_hdr, in_icmp_hdr, len);
	out_icmp_hdr->type = ICMP_ECHOREPLY;
	out_icmp_hdr->chksum = 0;
	out_icmp_hdr->chksum = chksum_internet((char *)out_icmp_hdr, len);

	/* send the echo reply */
	net_tx_ip_or_free(m, IPPROTO_ICMP, ntoh32(in_iphdr->saddr));
}

static void net_rx_icmp_echo_reply(struct icmp_hdr *in_icmp_hdr, uint16_t len)
{
	log_debug("icmp: received icmp echo reply");
}

void net_rx_icmp(struct mbuf *m, const struct ip_hdr *iphdr, uint16_t len)
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
	case ICMP_ECHOREPLY:
		net_rx_icmp_echo_reply(icmp_hdr, len);
		break;
	default:
		log_err("icmp: type %d not yet supported", icmp_hdr->type);
		break;
	}

drop:
	mbuf_free(m);
}

int net_tx_icmp(struct mbuf *m, uint8_t type, uint8_t code, uint32_t daddr,
		uint32_t header_data)
{
	struct icmp_pkt *icmp_pkt;

	log_debug("icmp: sending icmp with type %u, code %u\n", type, code);

	/* populate ICMP header */
	icmp_pkt = (struct icmp_pkt *)mbuf_push(m, ICMP_MINLEN);
	icmp_pkt->hdr.type = ICMP_ECHO;
	icmp_pkt->hdr.code = 0;
	icmp_pkt->icmp_void = hton32(header_data);
	icmp_pkt->hdr.chksum = 0;
	icmp_pkt->hdr.chksum = chksum_internet((char *)icmp_pkt, ICMP_MINLEN);

	return net_tx_ip(m, IPPROTO_ICMP, daddr);
}
