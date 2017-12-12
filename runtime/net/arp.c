/*
 * arp.c - support for address resolution protocol (ARP)
 */

#include <stddef.h>

#include <base/lock.h>
#include <base/log.h>
#include <net/arp.h>
#include <runtime/rculist.h>

#include "defs.h"

#define ARP_TABLE_CAPACITY 1024
#define ARP_EXPIRATION (1000 * ONE_SECOND)

/*
 * A single entry in the ARP table. The ip field is valid only if pending is NULL.
 */
struct arp_entry {
	struct ip_addr        ip;
	struct eth_addr       eth;
	struct mbuf*          pending;
	uint64_t              expiration;
	struct rcu_hlist_node link;
};

struct arp_state {
	spinlock_t            entries_lock;
	struct rcu_hlist_head entries[ARP_TABLE_CAPACITY];
	struct eth_addr       local_mac;
	struct ip_addr        local_ip;
};

static struct arp_state arp_state;

static int hash_ip(struct ip_addr ip) {
	return ip.addr % ARP_TABLE_CAPACITY;
}

static void update_entry(struct ip_addr ip, struct eth_addr eth) {
	int index;
	struct arp_entry* entry;
	struct rcu_hlist_node* node;
	struct mbuf* pending = NULL;

	index = hash_ip(ip);
	spin_lock(&arp_state.entries_lock);
	rcu_hlist_for_each(&arp_state.entries[index], node, true) {
		entry = rcu_hlist_entry(node, struct arp_entry, link);
		if(entry->eth.addr == eth.addr) {
			pending = entry->pending;
			((struct eth_hdr*)pending->data)->dhost = entry->eth;

			entry->pending = NULL;
			entry->ip = ip;
			entry->expiration = microtime() + ARP_EXPIRATION;
			goto out;
		}
	}

	entry = malloc(sizeof(struct arp_entry));
	entry->ip = ip;
	entry->eth = eth;
	entry->pending = NULL;

	rcu_hlist_add_head(&arp_state.entries[index], &entry->link);

 out:
	spin_unlock(&arp_state.entries_lock);
	if(pending)
		net_tx_xmit(pending);
}

int net_arp_init(struct eth_addr local_mac, struct ip_addr local_ip) {
	spin_lock_init(&arp_state.entries_lock);
	arp_state.local_mac = local_mac;
	arp_state.local_ip = local_ip;

	for(int i = 0; i < ARP_TABLE_CAPACITY; i++) {
		rcu_hlist_init_head(&arp_state.entries[i]);
	}

	return 0;
}

void net_rx_arp(struct mbuf *m) {
	int op;
	bool am_target;
	struct eth_hdr* eth_hdr;
	struct arp_hdr* arp_hdr;
	struct arp_hdr_ethip* arp_hdr_ethip;
	struct ip_addr sender_ip, target_ip;
	struct eth_addr sender_mac;

	eth_hdr = (struct eth_hdr*)mbuf_pull_or_null(m, sizeof(struct eth_hdr));
	arp_hdr = (struct arp_hdr*)mbuf_pull_or_null(m, sizeof(struct arp_hdr));
	arp_hdr_ethip = (struct arp_hdr_ethip*)
		mbuf_pull_or_null(m, sizeof(struct arp_hdr_ethip));

	if (!eth_hdr || !arp_hdr || !arp_hdr_ethip)
		goto out;

	/* make sure the arp header is valid */
	if (ntoh16(arp_hdr->htype) != ARP_HTYPE_ETHER ||
	    ntoh16(arp_hdr->ptype) != ETHTYPE_IP ||
	    arp_hdr->hlen != sizeof(struct eth_addr) ||
	    arp_hdr->plen != sizeof(struct ip_addr))
		goto out;

	op = ntoh16(arp_hdr->op);
	sender_ip.addr = ntoh32(arp_hdr_ethip->sender_ip.addr);
	target_ip.addr = ntoh32(arp_hdr_ethip->target_ip.addr);
	sender_mac = arp_hdr_ethip->sender_mac;

	/* refuse ARP packets with multicast source MAC's */
	if (sender_mac.addr[0] & ETH_ADDR_GROUP)
		goto out;

	am_target = (arp_state.local_ip.addr == target_ip.addr);
	update_entry(sender_ip, sender_mac);

	if (am_target && op == ARP_OP_REQUEST) {
		log_debug("arp: responding to arp request "
				  "from IP %d.%d.%d.%d\n",
				  ((sender_ip.addr >> 24) & 0xff),
				  ((sender_ip.addr >> 16) & 0xff),
				  ((sender_ip.addr >> 8) & 0xff),
				  (sender_ip.addr & 0xff));

		m = net_tx_alloc_mbuf();
		eth_hdr = (struct eth_hdr*)mbuf_put(m, sizeof(struct eth_hdr));
		eth_hdr->dhost = arp_hdr_ethip->target_mac;
		eth_hdr->shost = arp_state.local_mac;
		eth_hdr->type = hton16(ETHTYPE_ARP);

		arp_hdr = (struct arp_hdr*)mbuf_put(m, sizeof(struct arp_hdr));
		arp_hdr->htype = hton16(ARP_HTYPE_ETHER);
		arp_hdr->ptype = hton16(ETHTYPE_IP);
		arp_hdr->hlen = sizeof(struct eth_addr);
		arp_hdr->plen = sizeof(struct ip_addr);
		arp_hdr->op = hton16(ARP_OP_REPLY);

		arp_hdr_ethip = (struct arp_hdr_ethip*)mbuf_put(m, sizeof(struct arp_hdr_ethip));
		arp_hdr_ethip->target_ip.addr = hton16(sender_ip.addr);
		arp_hdr_ethip->target_mac = sender_mac;
		arp_hdr_ethip->sender_ip = arp_state.local_ip;
		arp_hdr_ethip->target_mac = arp_state.local_mac;

		net_tx_xmit(m);
		return;
	}

out:
	mbuf_free(m);
}

int net_tx_xmit_to_ip(struct mbuf *m, struct ip_addr dst_ip) {
	int index;
	struct arp_entry* entry;
	struct rcu_hlist_node* node;
	struct eth_hdr* eth_hdr;
	struct arp_hdr* arp_hdr;
	struct arp_hdr_ethip* arp_hdr_ethip;

	index = hash_ip(dst_ip);
	rcu_read_lock();
	rcu_hlist_for_each(&arp_state.entries[index], node, true) {
		entry = rcu_hlist_entry(node, struct arp_entry, link);
		if(entry->ip.addr == dst_ip.addr) {
			if(entry->pending == NULL) {
				((struct eth_hdr*)m->data)->dhost = entry->eth;
				rcu_read_unlock();
				return net_tx_xmit(m);
			} else {
				rcu_read_unlock();
				mbuf_free(m);
				return -1;
			}
		}
	}
	rcu_read_unlock();

	spin_lock(&arp_state.entries_lock);
	entry = malloc(sizeof(struct arp_entry));
	entry->ip = dst_ip;
	entry->pending = m;
	rcu_hlist_add_head(&arp_state.entries[index], &entry->link);
	spin_unlock(&arp_state.entries_lock);

	m = net_tx_alloc_mbuf();
	eth_hdr = (struct eth_hdr*)mbuf_put(m, sizeof(struct eth_hdr));
	eth_hdr->dhost = (struct eth_addr)ETH_ADDR_BROADCAST;
	eth_hdr->shost = arp_state.local_mac;
	eth_hdr->type = hton16(ETHTYPE_ARP);

	arp_hdr = (struct arp_hdr*)mbuf_put(m, sizeof(struct arp_hdr));
	arp_hdr->htype = hton16(ARP_HTYPE_ETHER);
	arp_hdr->ptype = hton16(ETHTYPE_IP);
	arp_hdr->hlen = sizeof(struct eth_addr);
	arp_hdr->plen = sizeof(struct ip_addr);
	arp_hdr->op = hton16(ARP_OP_REQUEST);

	arp_hdr_ethip = (struct arp_hdr_ethip*)mbuf_put(m, sizeof(struct arp_hdr_ethip));
	arp_hdr_ethip->sender_mac = arp_state.local_mac;
	arp_hdr_ethip->sender_ip = arp_state.local_ip;
	arp_hdr_ethip->target_ip = dst_ip;
	return net_tx_xmit(m);
}
