/*
 * arp.c - support for address resolution protocol (ARP)
 */

#include <stddef.h>

#include <base/lock.h>
#include <base/log.h>
#include <base/hash.h>
#include <net/arp.h>
#include <runtime/rculist.h>

#include "defs.h"

#define ARP_SEED		0xD4812A53
#define ARP_TABLE_CAPACITY	1024
#define ARP_EXPIRATION		(1000 * ONE_SECOND)

/*
 * A single entry in the ARP table. The ip field is valid only if pending is NULL.
 */
struct arp_entry {
	uint32_t		ip;
	struct eth_addr		eth;
	struct mbuf		*pending;
	uint64_t		expiration;
	struct rcu_hlist_node	link;
};

struct arp_state {
	spinlock_t		entries_lock;
	struct rcu_hlist_head	entries[ARP_TABLE_CAPACITY];
};

static struct arp_state arp_state;

static inline int hash_ip(uint32_t ip)
{
	return hash_crc32c_one(ARP_SEED, ip) % ARP_TABLE_CAPACITY;
}

static void update_entry(uint32_t ip, struct eth_addr eth)
{
	int index;
	struct arp_entry* entry;
	struct rcu_hlist_node* node;
	struct mbuf* pending = NULL;

	index = hash_ip(ip);
	spin_lock(&arp_state.entries_lock);
	rcu_hlist_for_each(&arp_state.entries[index], node,
			   spin_lock_held(&arp_state.entries_lock)) {
		entry = rcu_hlist_entry(node, struct arp_entry, link);
		if (entry->eth.addr == eth.addr) {
			pending = entry->pending;
			((struct eth_hdr*)pending->data)->dhost = entry->eth;

			entry->pending = NULL;
			entry->ip = ip;
			entry->expiration = microtime() + ARP_EXPIRATION;
			goto out;
		}
	}

	entry = malloc(sizeof(struct arp_entry));
	BUG_ON(!entry);
	entry->ip = ip;
	entry->eth = eth;
	entry->pending = NULL;

	rcu_hlist_add_head(&arp_state.entries[index], &entry->link);

 out:
	spin_unlock(&arp_state.entries_lock);
	if(pending)
		net_tx_xmit_or_free(pending);
}

static void arp_send(uint16_t op, struct eth_addr dhost, uint32_t daddr)
{
	struct mbuf *m;
	struct eth_hdr *eth_hdr;
	struct arp_hdr *arp_hdr;
	struct arp_hdr_ethip *arp_hdr_ethip;

	m = net_tx_alloc_mbuf();
	if (unlikely(!m))
		return;

	eth_hdr = mbuf_push_hdr(m, *eth_hdr);
	eth_hdr->shost = netcfg.mac;
	eth_hdr->dhost = dhost;
	eth_hdr->type = hton16(ETHTYPE_ARP);

	arp_hdr = mbuf_put_hdr(m, *arp_hdr);
	arp_hdr->htype = hton16(ARP_HTYPE_ETHER);
	arp_hdr->ptype = hton16(ETHTYPE_IP);
	arp_hdr->hlen = sizeof(struct eth_addr);
	arp_hdr->plen = sizeof(uint32_t);
	arp_hdr->op = hton16(op);

	arp_hdr_ethip = mbuf_put_hdr(m, *arp_hdr_ethip);
	arp_hdr_ethip->sender_mac = netcfg.mac;
	arp_hdr_ethip->sender_ip = hton32(netcfg.addr);
	arp_hdr_ethip->target_mac = dhost;
	arp_hdr_ethip->target_ip = hton32(daddr);

	net_tx_xmit_or_free(m);
}

void net_rx_arp(struct mbuf *m)
{
	uint16_t op;
	bool am_target;
	struct arp_hdr *arp_hdr;
	struct arp_hdr_ethip *arp_hdr_ethip;
	uint32_t sender_ip, target_ip;
	struct eth_addr sender_mac;

	arp_hdr = mbuf_pull_hdr_or_null(m, *arp_hdr);
	arp_hdr_ethip = mbuf_pull_hdr_or_null(m, *arp_hdr_ethip);
	if (!arp_hdr || !arp_hdr_ethip)
		goto out;

	/* make sure the arp header is valid */
	if (ntoh16(arp_hdr->htype) != ARP_HTYPE_ETHER ||
	    ntoh16(arp_hdr->ptype) != ETHTYPE_IP ||
	    arp_hdr->hlen != sizeof(struct eth_addr) ||
	    arp_hdr->plen != sizeof(uint32_t))
		goto out;

	op = ntoh16(arp_hdr->op);
	sender_ip = ntoh32(arp_hdr_ethip->sender_ip);
	target_ip = ntoh32(arp_hdr_ethip->target_ip);
	sender_mac = arp_hdr_ethip->sender_mac;

	/* refuse ARP packets with multicast source MAC's */
	if (sender_mac.addr[0] & ETH_ADDR_GROUP)
		goto out;

	am_target = (netcfg.addr == target_ip);
	update_entry(sender_ip, sender_mac);

	if (am_target && op == ARP_OP_REQUEST) {
		log_debug("arp: responding to arp request "
				  "from IP %d.%d.%d.%d",
				  ((sender_ip >> 24) & 0xff),
				  ((sender_ip >> 16) & 0xff),
				  ((sender_ip >> 8) & 0xff),
				  (sender_ip & 0xff));

		arp_send(ARP_OP_REPLY, sender_mac, sender_ip);
	}

out:
	mbuf_free(m);
}

/**
 * net_tx_xmit_to_ip - trasmits a packet to an IP address
 * @m: the mbuf to transmit
 * @daddr: the destination IP address (in native byte order)
 *
 * The payload must start with the network (L3) header. The ethernet header
 * will be prepended by this function.
 *
 * Returns 0 if successful, otherwise fail. If the successful, the mbuf will
 * be freed when the transmit completes. Otherwise, the mbuf still belongs to
 * the caller.
 */
int net_tx_xmit_to_ip(struct mbuf *m, uint32_t daddr)
{
	int index, ret;
	struct arp_entry* entry;
	struct rcu_hlist_node* node;
	struct eth_hdr *eth_hdr;

	eth_hdr = mbuf_push_hdr(m, *eth_hdr);
	eth_hdr->shost = netcfg.mac;
	eth_hdr->type = hton16(ETHTYPE_IP);

	if ((daddr & netcfg.netmask) != netcfg.network)
		daddr = netcfg.gateway;

	index = hash_ip(daddr);
	rcu_read_lock();
	rcu_hlist_for_each(&arp_state.entries[index], node, false) {
		entry = rcu_hlist_entry(node, struct arp_entry, link);
		if (entry->ip == daddr) {
			if (unlikely(entry->pending != NULL)) {
				rcu_read_unlock();
				mbuf_pull_hdr(m, *eth_hdr);
				return -EIO;
			}

			eth_hdr->dhost = entry->eth;
			rcu_read_unlock();
			ret = net_tx_xmit(m);
			if (unlikely(ret))
				mbuf_pull_hdr(m, *eth_hdr);
			return ret;
		}
	}
	rcu_read_unlock();

	entry = malloc(sizeof(*entry));
	BUG_ON(entry == NULL);
	entry->ip = daddr;
	entry->pending = m;

	spin_lock(&arp_state.entries_lock);
	rcu_hlist_add_head(&arp_state.entries[index], &entry->link);
	spin_unlock(&arp_state.entries_lock);

	arp_send(ARP_OP_REQUEST, eth_addr_broadcast, daddr);
	return 0;
}

int net_arp_init(void)
{
	int i;

	spin_lock_init(&arp_state.entries_lock);
	for (i = 0; i < ARP_TABLE_CAPACITY; i++)
		rcu_hlist_init_head(&arp_state.entries[i]);

	return 0;
}
