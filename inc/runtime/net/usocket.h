/*
 * usocket.h - UDP socket objects
 */

#pragma once

#include <net/mbuf.h>

struct addr {
	uint32_t ip;
	uint16_t port;
};

typedef void (*handler_fn_t)(int descriptor, struct mbuf *m, struct addr raddr);


extern int usocket_create(void);
extern int usocket_close(int desc);

extern void usocket_bind(int desc, struct addr laddr, handler_fn_t fn);
extern void usocket_connect(int desc, struct addr raddr);

extern struct mbuf *usocket_recv(int desc, struct addr *raddr);
extern int usocket_send(int desc, struct mbuf *m, struct addr raddr);
