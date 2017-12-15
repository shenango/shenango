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
	struct ip_addr        ip;
	struct eth_addr       eth;
	struct mbuf*          pending;
	uint64_t              expiration;
	struct rcu_hlist_node link;
};

struct arp_state {
	spinlock_t            entries_lock;
	struct rcu_hlist_head entries[ARP_TABLE_CAPACITY];
};

static struct arp_state arp_state;

static int hash_ip(struct ip_addr ip)
{
	return hash_crc32c_one(ARP_SEED, ip.addr) % ARP_TABLE_CAPACITY;
}

static void update_entry(struct ip_addr ip, struct eth_addr eth)
{
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
	BUG_ON(!entry);
	entry->ip = ip;
	entry->eth = eth;
	entry->pending = NULL;

	rcu_hlist_add_head(&arp_state.entries[index], &entry->link);

 out:
	spin_unlock(&arp_state.entries_lock);
	if(pending)
		net_tx_xmit(pending);
}

void net_rx_arp(struct mbuf *m)
{
	int op;
	bool am_target;
	struct mbuf* outgoing;
	struct eth_hdr* eth_hdr;
	struct arp_hdr* arp_hdr;
	struct arp_hdr_ethip* arp_hdr_ethip;
	struct ip_addr sender_ip, target_ip;
	struct eth_addr sender_mac;

	arp_hdr = (struct arp_hdr*)mbuf_pull_or_null(m, sizeof(struct arp_hdr));
	arp_hdr_ethip = (struct arp_hdr_ethip*)
		mbuf_pull_or_null(m, sizeof(struct arp_hdr_ethip));

	if (!arp_hdr || !arp_hdr_ethip)
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

	am_target = (netcfg.local_ip.addr == target_ip.addr);
	update_entry(sender_ip, sender_mac);

	if (am_target && op == ARP_OP_REQUEST) {
		log_debug("arp: responding to arp request "
				  "from IP %d.%d.%d.%d",
				  ((sender_ip.addr >> 24) & 0xff),
				  ((sender_ip.addr >> 16) & 0xff),
				  ((sender_ip.addr >> 8) & 0xff),
				  (sender_ip.addr & 0xff));

		outgoing = net_tx_alloc_mbuf();
		eth_hdr = (struct eth_hdr*)mbuf_put(outgoing, sizeof(struct eth_hdr));
		eth_hdr->dhost = arp_hdr_ethip->sender_mac;
		eth_hdr->shost = netcfg.local_mac;
		eth_hdr->type = hton16(ETHTYPE_ARP);

		arp_hdr = (struct arp_hdr*)mbuf_put(outgoing, sizeof(struct arp_hdr));
		arp_hdr->htype = hton16(ARP_HTYPE_ETHER);
		arp_hdr->ptype = hton16(ETHTYPE_IP);
		arp_hdr->hlen = sizeof(struct eth_addr);
		arp_hdr->plen = sizeof(struct ip_addr);
		arp_hdr->op = hton16(ARP_OP_REPLY);

		arp_hdr_ethip = (struct arp_hdr_ethip*)mbuf_put(outgoing, sizeof(struct arp_hdr_ethip));
		arp_hdr_ethip->target_ip.addr = hton32(sender_ip.addr);
		arp_hdr_ethip->target_mac = sender_mac;
		arp_hdr_ethip->sender_ip.addr = hton32(netcfg.local_ip.addr);
		arp_hdr_ethip->sender_mac = netcfg.local_mac;

		if (unlikely(net_tx_xmit(outgoing)))
			mbuf_free(outgoing);
	}

out:
	mbuf_free(m);
}

int net_tx_xmit_to_ip(struct mbuf *m, struct ip_addr dst_ip)
{
	int index;
	struct arp_entry* entry;
	struct rcu_hlist_node* node;
	struct eth_hdr* eth_hdr;
	struct arp_hdr* arp_hdr;
	struct arp_hdr_ethip* arp_hdr_ethip;

	eth_hdr = mbuf_push_hdr(m, *eth_hdr);
	eth_hdr->shost = netcfg.local_mac;
	eth_hdr->type = hton16(ETHTYPE_IP);

	if ((dst_ip.addr & netcfg.netmask.addr) != netcfg.network.addr)
		dst_ip.addr = netcfg.gateway.addr;

	index = hash_ip(dst_ip);
	rcu_read_lock();
	rcu_hlist_for_each(&arp_state.entries[index], node, false) {
		entry = rcu_hlist_entry(node, struct arp_entry, link);
		if (entry->ip.addr == dst_ip.addr) {
			if (entry->pending == NULL) {
				eth_hdr->dhost = entry->eth;
				rcu_read_unlock();
				return net_tx_xmit(m);
			} else {
				rcu_read_unlock();
				return -EIO;
			}
		}
	}
	rcu_read_unlock();

	entry = malloc(sizeof(*entry));
	BUG_ON(entry == NULL);
	entry->ip = dst_ip;
	entry->pending = m;

	spin_lock(&arp_state.entries_lock);
	rcu_hlist_add_head(&arp_state.entries[index], &entry->link);
	spin_unlock(&arp_state.entries_lock);

	m = net_tx_alloc_mbuf();
	if (unlikely(!m))
		return -ENOMEM;

	eth_hdr = mbuf_put_hdr(m, *eth_hdr);
	eth_hdr->dhost = (struct eth_addr)ETH_ADDR_BROADCAST;
	eth_hdr->shost = netcfg.local_mac;
	eth_hdr->type = hton16(ETHTYPE_ARP);

	arp_hdr = mbuf_put_hdr(m, *arp_hdr);
	arp_hdr->htype = hton16(ARP_HTYPE_ETHER);
	arp_hdr->ptype = hton16(ETHTYPE_IP);
	arp_hdr->hlen = sizeof(struct eth_addr);
	arp_hdr->plen = sizeof(struct ip_addr);
	arp_hdr->op = hton16(ARP_OP_REQUEST);

	arp_hdr_ethip = mbuf_put_hdr(m, *arp_hdr_ethip);
	arp_hdr_ethip->sender_mac = netcfg.local_mac;
	arp_hdr_ethip->sender_ip.addr = hton32(netcfg.local_ip.addr);
	arp_hdr_ethip->target_ip.addr = hton32(dst_ip.addr);

	return net_tx_xmit(m);
}

int net_arp_init(void)
{
	spin_lock_init(&arp_state.entries_lock);

	for (int i = 0; i < ARP_TABLE_CAPACITY; i++) {
		rcu_hlist_init_head(&arp_state.entries[i]);
	}

	return 0;
}
