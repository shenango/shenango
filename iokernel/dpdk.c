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
 * dpdk.c - the data-plane for the I/O kernel
 */

#include <stdint.h>
#include <inttypes.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include <base/log.h>
#include <base/mem.h>
#include <iokernel/queue.h>
#include <iokernel/shm.h>

#include "defs.h"

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
			.max_rx_pkt_len = ETHER_MAX_LEN,
			.hw_ip_checksum = 1,
	}
};
static struct shm_region ingress_mbuf_region;

/*
 * Callback to unmap the shared memory used by a mempool when destroying it.
 */
static void dpdk_mempool_memchunk_free(struct rte_mempool_memhdr *memhdr,
		void *opaque)
{
	mem_unmap_shm(opaque);
}

/*
 * Create and initialize a packet mbuf pool in shared memory, based on
 * rte_pktmbuf_pool_create.
 */
static struct rte_mempool *dpdk_pktmbuf_pool_create_in_shm(const char *name,
		unsigned n, unsigned cache_size, uint16_t priv_size,
		uint16_t data_room_size, int socket_id)
{
	unsigned elt_size;
	struct rte_pktmbuf_pool_private mbp_priv;
	struct rte_mempool *mp;
	int ret;
	void *shbuf;
	size_t total_elt_sz, pg_size, pg_shift, len;

	/* create rte_mempool */
	if (RTE_ALIGN(priv_size, RTE_MBUF_PRIV_ALIGN) != priv_size) {
		log_err("dpdk: mbuf priv_size=%u is not aligned", priv_size);
		goto fail;
	}
	elt_size = sizeof(struct rte_mbuf) + (unsigned) priv_size
			+ (unsigned) data_room_size;
	mbp_priv.mbuf_data_room_size = data_room_size;
	mbp_priv.mbuf_priv_size = priv_size;

	mp = rte_mempool_create_empty(name, n, elt_size, cache_size,
			sizeof(struct rte_pktmbuf_pool_private), socket_id, 0);
	if (mp == NULL)
		goto fail;

	ret = rte_mempool_set_ops_byname(mp, RTE_MBUF_DEFAULT_MEMPOOL_OPS, NULL);
	if (ret != 0) {
		log_err("dpdk: error setting mempool handler");
		goto fail_free_mempool;
	}
	rte_pktmbuf_pool_init(mp, &mbp_priv);

	/* check necessary size and map shared memory */
	total_elt_sz = mp->header_size + mp->elt_size + mp->trailer_size;
	pg_size = PGSIZE_2MB;
	pg_shift = rte_bsf32(pg_size);
	len = rte_mempool_xmem_size(n, total_elt_sz, pg_shift);
	if (len > INGRESS_MBUF_SHM_SIZE) {
		log_err("dpdk: shared memory is too small for number of mbufs");
		goto fail_free_mempool;
	}

	shbuf = mem_map_shm(INGRESS_MBUF_SHM_KEY, NULL, INGRESS_MBUF_SHM_SIZE,
			pg_size, true);
	if (shbuf == MAP_FAILED) {
		log_err("dpdk: mem_map_shm failed");
		goto fail_free_mempool;
	}
	ingress_mbuf_region.base = shbuf;
	ingress_mbuf_region.len = len;

	/* populate mempool using shared memory */
	ret = rte_mempool_populate_virt(mp, shbuf, len, pg_size,
			dpdk_mempool_memchunk_free, shbuf);
	if (ret < 0) {
		log_err("dpdk: error populating mempool %d", ret);
		goto fail_unmap_memory;
	}

	rte_mempool_obj_iter(mp, rte_pktmbuf_init, NULL);

	return mp;

fail_unmap_memory:
	mem_unmap_shm(shbuf);
fail_free_mempool:
	rte_mempool_free(mp);
fail:
	log_err("dpdk: couldn't create pktmbuf pool %s", name);
	return NULL;
}

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

	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), NULL);
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
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}

/*
 * Swap source and destination MAC addresses.
 */
void dpdk_swap_ether_src_dest(struct rte_mbuf *buf)
{
	struct ether_hdr *ptr_mac_hdr;
	struct ether_addr src_addr;

	ptr_mac_hdr = rte_pktmbuf_mtod(buf, struct ether_hdr *);
	ether_addr_copy(&ptr_mac_hdr->s_addr, &src_addr);
	ether_addr_copy(&ptr_mac_hdr->d_addr, &ptr_mac_hdr->s_addr);
	ether_addr_copy(&src_addr, &ptr_mac_hdr->d_addr);
}

/*
 * Swap source and destination IP addresses.
 */
void dpdk_swap_ip_src_dest(struct rte_mbuf *buf)
{
	struct ether_hdr *ptr_mac_hdr;
	uint16_t ether_type;
	struct ipv4_hdr *ptr_ipv4_hdr;
	uint32_t src_addr;

	/* Check that this is IPv4. TODO: support IPv6. */
	ptr_mac_hdr = rte_pktmbuf_mtod(buf, struct ether_hdr *);
	ether_type = ptr_mac_hdr->ether_type;
	if (ether_type != rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
		printf("WARNING: ether type %d is not supported\n", ether_type);
		return;
	}

	ptr_ipv4_hdr = rte_pktmbuf_mtod_offset(buf, struct ipv4_hdr *,
			sizeof(struct ether_hdr));
	src_addr = ptr_ipv4_hdr->src_addr;
	ptr_ipv4_hdr->src_addr = ptr_ipv4_hdr->dst_addr;
	ptr_ipv4_hdr->dst_addr = src_addr;
}

/*
 * Prepend preamble to ingress packets.
 */
static inline struct rx_net_hdr *dpdk_prepend_rx_preamble(struct rte_mbuf *buf)
{
	struct rx_net_hdr *net_hdr;
	uint64_t masked_ol_flags;

	net_hdr = (struct rx_net_hdr *) rte_pktmbuf_prepend(buf,
			(uint16_t) sizeof(*net_hdr));
	RTE_ASSERT(net_hdr != NULL);

	net_hdr->len = rte_pktmbuf_pkt_len(buf) - sizeof(*net_hdr);
	net_hdr->rss_hash = 0; /* unused for now */
	masked_ol_flags = buf->ol_flags & PKT_RX_IP_CKSUM_MASK;
	if (masked_ol_flags == PKT_RX_IP_CKSUM_GOOD)
		net_hdr->csum_type = CHECKSUM_TYPE_UNNECESSARY;
	else
		net_hdr->csum_type = CHECKSUM_TYPE_NEEDED;
	net_hdr->csum = 0; /* unused for now */

	return net_hdr;
}

/*
 * Process a batch of incoming packets.
 */
void dpdk_rx_burst(struct rte_mbuf **bufs, const uint16_t nb_rx)
{
	uint16_t i;
	struct rte_mbuf *buf;
	struct ether_hdr *ptr_mac_hdr;
	struct ether_addr *ptr_dst_addr;
	struct rx_net_hdr *net_hdr;

	for (i = 0; i < nb_rx; i++) {
		/* parse dst ether addr */
		buf = bufs[i];

		ptr_mac_hdr = rte_pktmbuf_mtod(buf, struct ether_hdr *);
		ptr_dst_addr = &ptr_mac_hdr->d_addr;
		printf("Packet to MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
				" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
				ptr_dst_addr->addr_bytes[0], ptr_dst_addr->addr_bytes[1],
				ptr_dst_addr->addr_bytes[2], ptr_dst_addr->addr_bytes[3],
				ptr_dst_addr->addr_bytes[4], ptr_dst_addr->addr_bytes[5]);

		/* swap src and dst ether and IP addresses. TODO: remove this once
		 * packets are sent up to the runtimes. */
		dpdk_swap_ether_src_dest(buf);
		dpdk_swap_ip_src_dest(buf);

		/* prepend ingress preamble */
		net_hdr = dpdk_prepend_rx_preamble(buf);
	}
}

/*
 * The main thread that does the work, reading from the port and echoing out
 * the same port.
 */
void dpdk_loop(uint8_t port)
{
	struct rte_mbuf *bufs[BURST_SIZE];
	uint16_t nb_rx, nb_tx, i;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	if (rte_eth_dev_socket_id(port) > 0
			&& rte_eth_dev_socket_id(port) != (int) rte_socket_id())
		printf("WARNING, port %u is on remote NUMA node to polling thread.\n\t"
				"Performance will not be optimal.\n", port);

	printf("\nCore %u echoing packets. [Ctrl+C to quit]\n", rte_lcore_id());

	/* Run until the application is quit or killed. */
	for (;;) {
		/*
		 * Receive packets on the port and echo them out the same port.
		 */

		/* Get burst of RX packets. */
		nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

		if (nb_rx == 0)
			continue;

		printf("received %d packets on port %d\n", nb_rx, port);

		dpdk_rx_burst(bufs, nb_rx);

		/* Send burst of TX packets. */
		nb_tx = rte_eth_tx_burst(port, 0, bufs, nb_rx);

		printf("sent %d packets on port %d\n", nb_tx, port);

		/* Free any unsent packets. */
		if (unlikely(nb_tx < nb_rx)) {
			for (i = nb_tx; i < nb_rx; i++)
				rte_pktmbuf_free(bufs[i]);
		}
	}
}

/*
 * Initialize dpdk.
 */
int dpdk_init(uint8_t port)
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	char *argv[] = { "./iokerneld", "-l", "2", "--socket-mem=128" };

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(sizeof(argv) / sizeof(argv[0]), argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	/* Check that there is a port to send/receive on. */
	nb_ports = rte_eth_dev_count();
	if (nb_ports < 1)
		rte_exit(EXIT_FAILURE, "Error: no available ports\n");

	/* Creates a new mempool in shared memory to hold the mbufs. */
	mbuf_pool = dpdk_pktmbuf_pool_create_in_shm("MBUF_POOL",
			NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize port. */
	if (dpdk_port_init(port, mbuf_pool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n", port);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	return 0;
}
