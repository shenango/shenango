/*
 * defs.h - local definitions for networking
 */

#pragma once

#include <net/mbuf.h>
#include <net/ethernet.h>
#include <net/ip.h>

#include "../defs.h"

/*
 * Network Error Reporting Functions
 */

extern void udp_error(struct mbuf *m, const struct ip_hdr *iphdr, int err);
extern void net_error(struct mbuf *m, int err);


/*
 * RX Networking Functions
 */

extern void net_rx_arp(struct mbuf *m);
extern void net_rx_icmp(struct mbuf *m, const struct ip_hdr *iphdr,
			uint16_t len);
extern void net_rx_udp(struct mbuf *m, const struct ip_hdr *iphdr,
		       uint16_t len);


/*
 * TX Networking Functions
 */

extern int arp_lookup(uint32_t daddr, struct eth_addr *dhost_out,
		      struct mbuf *m) __must_use_return;
extern struct mbuf *net_tx_alloc_mbuf(void);
extern void net_tx_release_mbuf(struct mbuf *m);
extern int net_tx_eth(struct mbuf *m, uint16_t proto,
		      struct eth_addr dhost) __must_use_return;
extern int net_tx_ip(struct mbuf *m, uint8_t proto,
		     uint32_t daddr) __must_use_return;
extern int net_tx_icmp(struct mbuf *m, uint8_t type, uint8_t code,
		uint32_t daddr, uint16_t id, uint16_t seq) __must_use_return;

/**
 * net_tx_eth - transmits an ethernet packet, or frees it on failure
 * @m: the mbuf to transmit
 * @type: the ethernet type (in native byte order)
 * @dhost: the destination MAC address
 *
 * The payload must start with the network (L3) header. The ethernet (L2)
 * header will be prepended by this function.
 *
 * @m must have been allocated with net_tx_alloc_mbuf().
 */
static inline void net_tx_eth_or_free(struct mbuf *m, uint16_t type,
				      struct eth_addr dhost)
{
	if (unlikely(net_tx_eth(m, type, dhost) != 0))
		mbuf_free(m);
}

/**
 * net_tx_ip - transmits an IP packet, or frees it on failure
 * @m: the mbuf to transmit
 * @proto: the transport protocol
 * @daddr: the destination IP address (in native byte order)
 *
 * The payload must start with the transport (L4) header. The IPv4 (L3) and
 * ethernet (L2) headers will be prepended by this function.
 *
 * @m must have been allocated with net_tx_alloc_mbuf().
 */
static inline void net_tx_ip_or_free(struct mbuf *m, uint8_t proto,
				     uint32_t daddr)
{
	if (unlikely(net_tx_ip(m, proto, daddr) != 0))
		mbuf_free(m);
}

/**
 * mbuf_drop - frees an mbuf, counting it as a drop
 * @m: the mbuf to free
 */
static inline void mbuf_drop(struct mbuf *m)
{
	mbuf_free(m);
	STAT(DROPS)++;
}
