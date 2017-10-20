/*
 * ethqueue.h - ethernet queue support
 */

#pragma once

#include <net/mbuf.h>


/*
 * Recieve Queue API
 */

struct eth_rx_queue {
	int (*recv)	(struct eth_rx_queue *rx, int nr, struct mbuf **pkts);
};

/**
 * eth_rx_recv - receive packets on an RX queue
 * @rx: the RX queue
 * @nr: the length of the array, determining the max batch size
 * @pkts: an array to store received packets
 *
 * Returns the number of packets received, a value less than or equal to @nr.
 * A negative return value indicates an error occurred.
 */
static inline int
eth_rx_recv(struct eth_rx_queue *rx, int nr, struct mbuf **pkts)
{
	return rx->recv(rx, nr, pkts);
}


/*
 * Transmit Queue API
 */

struct eth_tx_queue {
	int (*reclaim)	(struct eth_tx_queue *tx);
	int (*xmit)	(struct eth_tx_queue *tx, int nr, struct mbuf **pkts);
};

/**
 * eth_tx_reclaim - scans the queue and reclaims finished buffers
 * @tx: the TX queue
 *
 * NOTE: scatter-gather mbuf's can span multiple descriptors, so
 * take that into account when interpreting the count provided by
 * this function.
 *
 * Returns an available descriptor count.
 */
static inline int eth_tx_reclaim(struct eth_tx_queue *tx)
{
	return tx->reclaim(tx);
}

/**
 * eth_tx_xmit - transmits packets on a TX queue
 * @tx: the TX queue
 * @nr: the number of mbufs to transmit
 * @mbufs: an array of mbufs to tranmsit
 *
 * Returns the number of mbuf's transmitted.
 */
static inline int
eth_tx_xmit(struct eth_tx_queue *tx, int nr, struct mbuf **mbufs)
{
	return tx->xmit(tx, nr, mbufs);
}
