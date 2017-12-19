/*
 * ping.c - simple ping utility
 */

#include <base/compiler.h>
#include <base/log.h>
#include <net/icmp.h>

#include "defs.h"

void net_send_ping(uint16_t id, uint16_t seq_num, uint32_t daddr)
{
	struct mbuf *m;
	uint32_t header_data;

	log_debug("ping: sending ping with id %u, seq_num %u to %u", id, seq_num,
			daddr);

	m = net_tx_alloc_mbuf();
	if (unlikely(!m))
		return;

	header_data = id << 16 | seq_num;
	if (unlikely(net_tx_icmp(m, ICMP_ECHO, 0, daddr, header_data) != 0))
		mbuf_free(m);
}
