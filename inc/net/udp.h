/*
 * udp.h - User Datagram Protocol
 */

#pragma once

#include <base/types.h>

struct udp_hdr {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t len;
	uint16_t chksum;
};
