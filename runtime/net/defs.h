/*
 * defs.h - local definitions for networking
 */

#pragma once

#include <net/mbuf.h>
#include <net/ethernet.h>
#include <net/ip.h>
#include <runtime/rculist.h>

#include "../defs.h"

/*
 * Initialization
 */

extern int net_arp_init(struct eth_addr, struct ip_addr);


/*
 * RX Networking Functions
 */

extern void net_rx_icmp(struct mbuf *m, struct ip_hdr *iphdr, uint16_t len);
extern void net_rx_udp(struct mbuf *m, struct ip_addr *src, uint16_t len);
extern void net_rx_arp(struct mbuf *m);


/*
 * TX Networking Functions
 */

extern struct mbuf *net_tx_alloc_mbuf(void);
extern void net_tx_release_mbuf(struct mbuf *m);
extern int net_tx_xmit(struct mbuf *m);
extern int net_tx_xmit_to_ip(struct mbuf *m, struct ip_addr dst_ip);
