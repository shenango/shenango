/*
 * net.h - shared network definitions
 */

#pragma once

struct netaddr {
	uint32_t ip;
	uint16_t port;
};

extern int str_to_netaddr(const char *str, struct netaddr *addr);
