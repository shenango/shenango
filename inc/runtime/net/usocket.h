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
extern void usocket_close(int desc);

extern int usocket_bind_queue(int desc, struct addr laddr);
extern int usocket_bind_handler(int desc, struct addr laddr, handler_fn_t fn);
extern int usocket_connect(int desc, struct addr raddr);

extern struct mbuf *usocket_recv(int desc, struct addr *raddr, bool block);
extern int usocket_send(int desc, struct mbuf *m, struct addr raddr);
