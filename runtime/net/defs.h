/*
 * defs.h - local definitions for networking
 */

#pragma once

#include <net/mbuf.h>
#include <net/ethernet.h>
#include <net/ip.h>

#include "../defs.h"


/*
 * Initialization
 */

extern int net_arp_init(void);
extern int usocket_init(void);
extern int usocket_init_thread(void);


/*
 * RX Networking Functions
 */

extern void net_rx_icmp(struct mbuf *m, const struct ip_hdr *iphdr, uint16_t len);
extern void net_rx_udp_dump(struct mbuf *m, uint32_t saddr, uint16_t len);
extern void net_rx_arp(struct mbuf *m);

extern void net_rx_udp_usocket(struct mbuf *m, const struct ip_hdr *iphdr, uint16_t len);


/*
 * TX Networking Functions
 */

extern struct mbuf *net_tx_alloc_mbuf(void);
extern void net_tx_release_mbuf(struct mbuf *m);
extern int net_tx_xmit(struct mbuf *m) __must_use_return;
extern int net_tx_xmit_to_ip(struct mbuf *m, uint32_t daddr) __must_use_return;
extern int net_tx_ip(struct mbuf *m, uint8_t proto, uint32_t daddr) __must_use_return;
extern int net_tx_icmp(struct mbuf *m, uint8_t type, uint8_t code,
		uint32_t daddr, uint32_t header_data) __must_use_return;

/**
 * net_tx_xmit_or_free - transmits an mbuf, freeing it if the transmit fails
 * @m: the mbuf to transmit
 */
static inline void net_tx_xmit_or_free(struct mbuf *m)
{
	if (unlikely(net_tx_xmit(m) != 0))
		mbuf_free(m);
}

/**
 * net_tx_xmit_to_ip_or_free - transmits an mbuf to an IP address, freeing it
 * if the transmit fails
 * @m: the mbuf to transmit
 * @daddr: the destination IP address
 */
static inline void net_tx_xmit_to_ip_or_free(struct mbuf *m, uint32_t daddr)
{
	if (unlikely(net_tx_xmit_to_ip(m, daddr) != 0))
		mbuf_free(m);
}
