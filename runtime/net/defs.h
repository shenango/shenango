/*
 * defs.h - local definitions for networking
 */

#pragma once

#include <net/mbuf.h>
#include <net/ethernet.h>
#include <net/ip.h>
#include <runtime/rculist.h>

/*
 * Initialization
 */

extern int net_arp_init(struct eth_addr, struct ip_addr);

/*
 * RX Networking Functions
 */

enum {
	/*
	 * Capture packets delivered to a local port from any source (3-tuple).
	 * Uses: protocol, dst_port
	 */
	RX_HANDLER_MODE_ENDPOINT = 0,

	/*
	 * Capture packets delivered from a specific source (5-tuple).
	 * Uses: protocol, src_ip, src_port, dst_port
	 * This mode has priority over RX_HANDLER_MODE_ENDPOINT.
	 */
	RX_HANDLER_MODE_CONNECTION,
};

struct rx_handler {
	struct rcu_hlist_node	link;
	int			mode;
	struct ip_addr		src_ip;
	unsigned short		protocol, src_port, dst_port;
	void (*recv) (struct mbuf *m, struct rx_handler *h);
};

extern int net_rx_register_handler(struct rx_handler *h);
extern void net_rx_unregister_handler(struct rx_handler *h);
extern void net_rx_arp(struct mbuf *m);


/*
 * TX Networking Functions
 */

extern struct mbuf *net_tx_alloc_mbuf(void);
extern void net_tx_release_mbuf(struct mbuf *m);
extern int net_tx_xmit(struct mbuf *m);
extern int net_tx_xmit_to_ip(struct mbuf *m, struct ip_addr dst_ip);
