/*
 * udp.c - support for User Datagram Protocol (UDP)
 */

#include "defs.h"

#include <net/udp.h>
#include <runtime/chan.h>
#include <runtime/rculist.h>
#include <runtime/net/usocket.h>

/** UDP socket stuff **/
#define NUSOCKET 512
#define PKT_QUEUE_CAPACITY 128
#define USOCKET_TABLE_CAPACITY 1024

enum { STATE_UNUSED = 0,
       STATE_INIT,
       STATE_BOUND_QUEUE,
       STATE_BOUND_CALLBACK,
};

struct usocket {
	int descriptor;
	unsigned int state;
	struct rcu_hlist_node link;
	struct addr laddr;
	struct addr raddr;
	handler_fn_t *handler;
	struct chan pktq;
};

DEFINE_SPINLOCK(usocket_lock);
struct usocket usockets[NUSOCKET];
struct rcu_hlist_head socketmap[USOCKET_TABLE_CAPACITY];


void dump_udp_pkt(int loglvl, uint32_t saddr,
		  struct udp_hdr *udp_hdr, void *data);

void net_rx_udp_dump(struct mbuf *m, uint32_t saddr, uint16_t len)
{
	struct udp_hdr *hdr;

	hdr = mbuf_pull_hdr_or_null(m, *hdr);
	if (unlikely(!hdr))
		goto drop;

	if (unlikely(ntoh16(hdr->len) != len))
		goto drop;


	dump_udp_pkt(0, saddr, hdr, mbuf_data(m));

	// return;

drop:
	mbuf_free(m);
}

