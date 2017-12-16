/*
 * arp.h - Address Resolution Protocol (RFC 826, RFC 903)
 */

#pragma once

#include <base/stddef.h>
#include <net/ethernet.h>
#include <net/ip.h>

struct arp_hdr {
	uint16_t htype;
	uint16_t ptype;		/* the ETHERTYPE */
	uint8_t  hlen;
	uint8_t  plen;
	uint16_t op;

	/*
	 * Variable length fields continue as follows:
	 *    sender hw addr: hlen bytes
	 *    sender protocol addr: plen bytes
	 *    target hw addr: hlen bytes
	 *    target protocol addr: plen bytes
	 */
} __packed;

struct arp_hdr_ethip {
	struct eth_addr	sender_mac;
	uint32_t	sender_ip;
	struct eth_addr	target_mac;
	uint32_t	target_ip;
} __packed;

#define ARP_HTYPE_ETHER		1	/* ethernet */
#define ARP_HTYPE_IEEE802	6	/* token-ring */
#define ARP_HTYPE_ARCNET	7	/* arcnet */
#define ARP_HTYPE_FRELAY	16	/* frame relay */
#define ARP_HTYPE_IEEE1394	24	/* firewire */
#define ARP_HTYPE_INFINIBAND	32	/* infiniband */

enum {
	ARP_OP_REQUEST = 1,	/* request hw addr given protocol addr */
	ARP_OP_REPLY = 2,	/* response hw addr given protocol addr  */
	ARP_OP_REVREQUEST = 3,	/* request protocol addr given hw addr */
	ARP_OP_REVREPLY = 4,	/* response protocol addr given hw addr */
};
