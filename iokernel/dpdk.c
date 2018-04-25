/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * dpdk.c - DPDK initialization for the iokernel dataplane
 */

#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>

#include <base/log.h>

#include "defs.h"

#define RX_RING_SIZE 128
#define TX_RING_SIZE 128

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = ETHER_MAX_LEN,
		.hw_ip_checksum = 0,
		.mq_mode = ETH_MQ_RX_RSS,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_UDP,
		},
	},
};

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int dpdk_port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf;

	if (port >= rte_eth_dev_count())
		return -1;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	/* Enable TX offloading */
	rte_eth_dev_info_get(0, &dev_info);
	txconf = &dev_info.default_txconf;
#if 0
	txconf->txq_flags &= ~(ETH_TXQ_FLAGS_NOXSUMUDP |
			ETH_TXQ_FLAGS_NOXSUMTCP);
#endif

	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), txconf);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	log_info("dpdk: port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}

/*
 * Log some ethernet port stats.
 */
void dpdk_print_eth_stats()
{
	int ret;
	struct rte_eth_stats stats;

	ret = rte_eth_stats_get(dp.port, &stats);
	if (ret)
		log_debug("dpdk: error getting eth stats");

	log_debug("eth stats for port %d at time %"PRIu64, dp.port, microtime());
	log_debug("RX-packets: %"PRIu64" RX-dropped: %"PRIu64" RX-bytes: %"PRIu64,
			stats.ipackets, stats.imissed, stats.ibytes);
	log_debug("TX-packets: %"PRIu64" TX-bytes: %"PRIu64, stats.opackets,
			stats.obytes);
	log_debug("RX-error: %"PRIu64" TX-error: %"PRIu64" RX-mbuf-fail: %"PRIu64,
			stats.ierrors, stats.oerrors, stats.rx_nombuf);
}

/*
 * Initialize dpdk, must be done as soon as possible.
 */
int dpdk_init()
{
	unsigned nb_ports;
	char *argv[4];
	char buf[10];

	/* init args */
	argv[0] = "./iokerneld";
	argv[1] = "-l";
	/* use our assigned core */
	sprintf(buf, "%d", core_assign.dp_core);
	argv[2] = buf;
	argv[3] = "--socket-mem=128";

	/* initialize the Environment Abstraction Layer (EAL) */
	int ret = rte_eal_init(sizeof(argv) / sizeof(argv[0]), argv);
	if (ret < 0) {
		log_err("dpdk: error with EAL initialization");
		return -1;
	}

	/* check that there is a port to send/receive on */
	nb_ports = rte_eth_dev_count();
	if (nb_ports < 1) {
		log_err("dpdk: no available ports");
		return -1;
	}

	if (rte_lcore_count() > 1)
		log_warn("dpdk: too many lcores enabled, only 1 used");

	return 0;
}

/*
 * Additional dpdk initialization that must be done after rx init.
 */
int dpdk_late_init()
{
	/* initialize port */
	dp.port = 0;
	if (dpdk_port_init(dp.port, dp.rx_mbuf_pool) != 0) {
		log_err("dpdk: cannot init port %"PRIu8 "\n", dp.port);
		return -1;
	}

	return 0;
}
