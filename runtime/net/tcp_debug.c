/*
 * tcp_debug.c - prints TCP debug information
 */

#include <string.h>

#include <base/stddef.h>
#include <base/log.h>

#include "tcp.h"

#if defined(DEBUG)
#define TCP_FLAG_STR_LEN 25

static void tcp_flags_to_str(uint8_t flags, char *str)
{
	bool first_flag = false;

	if (flags & TCP_SYN) {
		strcpy(str, "SYN");
		first_flag = true;
	}
	if (flags & TCP_ACK) {
		if (!first_flag) {
			strcpy(str, "ACK");
			first_flag = true;
		} else
			strcat(str, "|ACK");
	}
	if (flags & TCP_PUSH) {
		if (!first_flag) {
			strcpy(str, "PUSH");
			first_flag = true;
		} else
			strcat(str, "|PUSH");
	}
	if (flags & TCP_FIN) {
		if (!first_flag) {
			strcpy(str, "FIN");
			first_flag = true;
		} else
			strcat(str, "|FIN");
	}
	if (flags & TCP_URG) {
		if (!first_flag) {
			strcpy(str, "URG");
			first_flag = true;
		} else
			strcat(str, "|URG");
	}
	if (flags & TCP_RST) {
		if (!first_flag) {
			strcpy(str, "RST");
			first_flag = true;
		} else
			strcat(str, "|RST");
	}
	if (!first_flag)
		strcpy(str, ".");
}

static void tcp_dump_pkt(tcpconn_t *c, const struct tcp_hdr *tcphdr,
			 uint32_t len, bool egress)
{
	char in_ip[IP_ADDR_STR_LEN];
	char out_ip[IP_ADDR_STR_LEN];
	char flags[TCP_FLAG_STR_LEN];
	uint32_t ack, seq;
	uint16_t in_port, out_port;
	uint16_t wnd;

	wnd = ntoh16(tcphdr->win);

	if (egress) {
		ip_addr_to_str(c->e.laddr.ip, in_ip);
		ip_addr_to_str(c->e.raddr.ip, out_ip);
		ack = ntoh32(tcphdr->ack) - c->pcb.irs;
		seq = ntoh32(tcphdr->seq) - c->pcb.iss;
		in_port = c->e.laddr.port;
		out_port = c->e.raddr.port;
	} else {
		ip_addr_to_str(c->e.laddr.ip, out_ip);
		ip_addr_to_str(c->e.raddr.ip, in_ip);
		ack = ntoh32(tcphdr->ack) - c->pcb.iss;
		seq = ntoh32(tcphdr->seq) - c->pcb.irs;
		out_port = c->e.laddr.port;
		in_port = c->e.raddr.port;
	}

	tcp_flags_to_str(tcphdr->flags, flags);

	log_debug("tcp: %p %s:%hu -> %s:%hu "
		  "FLAGS=%s SEQ=ISS+%u ACK=IRS+%u WND=%u LEN=%u",
		  c, in_ip, in_port, out_ip, out_port,
		  flags, seq, ack, wnd, len); 

}

/* prints an outgoing TCP packet */
void tcp_debug_egress_pkt(tcpconn_t *c, struct mbuf *m)
{
	tcp_dump_pkt(c, (struct tcp_hdr *)mbuf_data(m),
		     mbuf_length(m) - sizeof(struct tcp_hdr), true);
}

/* prints an incoming TCP packet */
void tcp_debug_ingress_pkt(tcpconn_t *c, struct mbuf *m)
{
	tcp_dump_pkt(c, (struct tcp_hdr *)mbuf_transport_offset(m),
		     mbuf_length(m), false);
}

static const char *state_names[] = {
	"SYN-SENT",
	"SYN-RECEIVED",
	"ESTABLISHED",
	"FIN-WAIT1",
	"FIN-WAIT2",
	"CLOSE-WAIT",
	"CLOSING",
	"LAST-ACK",
	"TIME-WAIT",
	"CLOSED",
};

/* prints a TCP state change */
void tcp_debug_state_change(tcpconn_t *c, int last, int next)
{
	if (last == TCP_STATE_CLOSED) {
		log_debug("tcp: %p CREATE -> %s", c, state_names[next]);
	} else {
		log_debug("tcp: %p %s -> %s", c, state_names[last],
			  state_names[next]);
	}
}
#endif
