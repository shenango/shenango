/*
 * arp.c - support for address resolution protocol (ARP)
 */

#include <stddef.h>
#include <net/arp.h>

#include "defs.h"

void net_rx_arp(struct mbuf *m)
{

}

int net_tx_xmit_to_ip(struct mbuf *m, struct ip_addr *dst_ip)
{
	return -ENOSYS;
}
