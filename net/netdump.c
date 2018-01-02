/*
 * netdump.c - logs network headers in a human-readable format
 *
 * This collection of utility functions is primarly intended
 * for debugging, but could also serve a role in error reporting.
 */

#include <stdio.h>

#include <base/stddef.h>
#include <base/log.h>
#include <base/byteorder.h>
#include <net/ethernet.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/udp.h>

/**
 * dump_eth_pkt - prints an ethernet header
 * @loglvl: the log level to use
 * @hdr: the ethernet header
 */
void dump_eth_pkt(int loglvl, struct eth_hdr *hdr)
{
        struct eth_addr *dmac = &hdr->dhost;
        struct eth_addr *smac = &hdr->shost;

	logk(loglvl, "ETHERNET packet dump\n");
        logk(loglvl, "\tdst MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
             dmac->addr[0], dmac->addr[1], dmac->addr[2],
             dmac->addr[3], dmac->addr[4], dmac->addr[5]);
        logk(loglvl, "\tsrc MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
             smac->addr[0], smac->addr[1], smac->addr[2],
             smac->addr[3], smac->addr[4], smac->addr[5]);
        logk(loglvl, "\tframe type: %x\n", ntoh16(hdr->type));
}

/**
 * dump_arp_pkt - prints an arp header
 * @loglvl: the log level to use
 * @arphdr: the arp header
 * @ethip: the arp payload (can be NULL)
 *
 * If @ethip is NULL, then assumes an unsupported htype and/or ptype.
 */
void dump_arp_pkt(int loglvl,
		  struct arp_hdr *arphdr,
		  struct arp_hdr_ethip *ethip)
{
        struct eth_addr *smac = &ethip->sender_mac;
        struct eth_addr *tmac = &ethip->target_mac;
	uint16_t op;
        uint32_t sip, tip;

	op = ntoh16(arphdr->op);
        sip = ntoh32(ethip->sender_ip);
        tip = ntoh32(ethip->target_ip);

        logk(loglvl, "ARP packet dump: op %s\n",
             (op == ARP_OP_REQUEST) ? "request" : "response");

	if (!ethip) {
		logk(loglvl, "\tunsupported htype %d, ptype %d\n",
		     ntoh16(arphdr->htype), ntoh16(arphdr->ptype));
		return;
	}

        logk(loglvl, "\tsender MAC:\t%02X:%02X:%02X:%02X:%02X:%02X\n",
             smac->addr[0], smac->addr[1], smac->addr[2],
             smac->addr[3], smac->addr[4], smac->addr[5]);
        logk(loglvl, "\tsender IP:\t%d.%d.%d.%d\n",
             ((sip >> 24) & 0xff), ((sip >> 16) & 0xff),
             ((sip >> 8) & 0xff), (sip & 0xff));
        logk(loglvl, "\ttarget MAC:\t%02X:%02X:%02X:%02X:%02X:%02X\n",
             tmac->addr[0], tmac->addr[1], tmac->addr[2],
             tmac->addr[3], tmac->addr[4], tmac->addr[5]);
        logk(loglvl, "\ttarget IP:\t%d.%d.%d.%d\n",
             ((tip >> 24) & 0xff), ((tip >> 16) & 0xff),
             ((tip >> 8) & 0xff), (tip & 0xff));
}

void dump_udp_pkt(int loglvl, uint32_t saddr, struct udp_hdr *udp_hdr,
          void *data)
{
    char sip[IP_ADDR_STR_LEN];
    char line[256];
    uint16_t sport, dport, len;
    size_t c, d;
    int i, j, k;

    ip_addr_to_str(saddr, sip);
    sport = ntoh16(udp_hdr->src_port);
    dport = ntoh16(udp_hdr->dst_port);
    len = ntoh16(udp_hdr->len) - sizeof(*udp_hdr);

    logk(loglvl, "UDP packet received from %s:%d on port %d", sip, sport,
         dport);
    for (c = 0; c < len;) {
        d = snprintf(line, 256, "%016lx: ", c);
        for (i = 0; i < 8 && c < len; i++) {
            for (j = 0; j < 2 && c < len; j++, c++) {
                k = *(((char *)data) + c);
                d += snprintf(line + d, 256 - d, "%02x", k);
            }
            d += snprintf(line + d, 256 - d, " ");
        }
        line[d] = 0;
        logk(loglvl, "%s", line);
    }
}

/**
 * ip_addr_to_str - prints an IP address as a human-readable string
 * @addr: the ip address
 * @str: a buffer to store the string
 *
 * The buffer must be IP_ADDR_STR_LEN in size.
 */
char *ip_addr_to_str(uint32_t addr, char *str)
{
	snprintf(str, IP_ADDR_STR_LEN, "%d.%d.%d.%d",
		 ((addr >> 24) & 0xff),
                 ((addr >> 16) & 0xff),
                 ((addr >> 8) & 0xff),
                 (addr & 0xff));
	return str;
}
