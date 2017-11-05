/*
 * ixgbe_rxtx.c - IXGBE RX and TX queue support
 */

#include <base/stddef.h>
#include <base/byteorder.h>
#include <base/time.h>
#include <base/atomic.h>
#include <base/log.h>
#include <base/page.h>
#include <net/mbuf.h>
#include <net/ethdev.h>
#include <asm/ops.h>

#include "ixgbe_api.h"
#include "ixgbe_vf.h"
#include "ixgbe_dcb.h"
#include "ixgbe_common.h"
#include "ixgbe_ethdev.h"

#define IXGBE_ALIGN		128
#define IXGBE_MIN_RING_DESC	64
#define IXGBE_MAX_RING_DESC	4096
#define IXGBE_RDT_THRESH	32
#define IXGBE_MBUF_LEN		2048

/* hardware requirements on IXGBE_MBUF_LEN */
BUILD_ASSERT(IXGBE_MBUF_LEN % 1024 == 0);
BUILD_ASSERT(IXGBE_MBUF_LEN >= 2048);

struct rx_entry {
	struct mbuf *mbuf;
};

struct rx_queue {
	struct eth_rx_queue	erxq;
	volatile union ixgbe_adv_rx_desc *ring;
	physaddr_t		ring_physaddr;
	struct mbuf_allocator	*alloc;
	struct rx_entry		*ring_entries;

	volatile uint32_t	*rdt_reg_addr;
	volatile uint32_t	*rdh_reg_addr;
	uint16_t		reg_idx;
	uint16_t		queue_id;

	uint16_t		head;
	uint16_t		tail;
	uint16_t		len;
};

#define eth_rx_queue_to_drv(rxq) container_of(rxq, struct rx_queue, erxq)

/**
 * IXGBE CTX Constants
 */
enum ixgbe_advctx_num {
	IXGBE_CTX_0    = 0, /**< CTX0 */
	IXGBE_CTX_1    = 1, /**< CTX1  */
	IXGBE_CTX_NUM  = 2, /**< CTX NUMBER  */
};

/**
 * Structure to check if new context need be built
 */
struct ixgbe_advctx_info {
	uint16_t flags;           /**< ol_flags for context build. */
};

struct tx_entry {
	struct mbuf *mbuf;
};

struct tx_queue {
	struct eth_tx_queue	etxq;
	volatile union ixgbe_adv_tx_desc *ring;
	physaddr_t		ring_physaddr;
	struct tx_entry		*ring_entries;

	volatile uint32_t	*tdt_reg_addr;
	uint16_t		reg_idx;
	uint16_t		queue_id;

	uint16_t		head;
	uint16_t		tail;
	uint16_t		len;

	uint16_t		ctx_curr;
	struct ixgbe_advctx_info ctx_cache[IXGBE_CTX_NUM];
};

#define eth_tx_queue_to_drv(txq) container_of(txq, struct tx_queue, etxq)

static void ixgbe_clear_rx_queue(struct rx_queue *rxq)
{
	int i;

	for (i = 0; i < rxq->len; i++) {
		if (rxq->ring_entries[i].mbuf) {
			mbuf_free(rxq->ring_entries[i].mbuf);
			rxq->ring_entries[i].mbuf = NULL;
		}
	}

	rxq->head = 0;
	rxq->tail = rxq->len - 1;
}

static int ixgbe_alloc_rx_mbufs(struct rx_queue *rxq)
{
	int i;

	for (i = 0; i < rxq->len; i++) {
		physaddr_t phys;
		struct mbuf *b = mbuf_alloc(rxq->alloc);
		if (unlikely(!b))
			goto fail;

		assert(mbuf_tailroom(b) >= IXGBE_MBUF_LEN);
		rxq->ring_entries[i].mbuf = b;
		phys = mbuf_data_phys(b);
		rxq->ring[i].read.hdr_addr = cpu_to_le32(phys);
		rxq->ring[i].read.pkt_addr = cpu_to_le32(phys);
	}

	return 0;

fail:
	for (i--; i >= 0; i--)
		mbuf_free(rxq->ring_entries[i].mbuf);
	return -ENOMEM;
}

static int ixgbe_rx_recv(struct eth_rx_queue *rx, int nr, struct mbuf **pkts)
{
	struct rx_queue *rxq = eth_rx_queue_to_drv(rx);
	volatile union ixgbe_adv_rx_desc *rxdp;
	union ixgbe_adv_rx_desc rxd;
	struct mbuf *b, *new_b;
	struct rx_entry *rxqe;
	physaddr_t paddr;
	uint32_t status;
	int nb_descs = 0;
	bool valid_checksum;

	assert(nr > 0);

	do {
		rxdp = &rxq->ring[rxq->head & (rxq->len - 1)];
		status = le32_to_cpu(rxdp->wb.upper.status_error);
		valid_checksum = true;

		if (!(status & IXGBE_RXDADV_STAT_DD))
			break;

		rxd = *rxdp;
		rxqe = &rxq->ring_entries[rxq->head & (rxq->len -1)];

		/* Check IP checksum calculated by hardware (if applicable) */
		if (unlikely((rxdp->wb.upper.status_error & IXGBE_RXD_STAT_IPCS) &&
			     (rxdp->wb.upper.status_error & IXGBE_RXDADV_ERR_IPE))) {
			log_err("ixgbe: IP RX checksum error, dropping pkt\n");
			valid_checksum = false;
		}

		/* Check TCP checksum calculated by hardware (if applicable) */
		if (unlikely((rxdp->wb.upper.status_error & IXGBE_RXD_STAT_L4CS) &&
			     (rxdp->wb.upper.status_error & IXGBE_RXDADV_ERR_TCPE))) {
			log_err("ixgbe: TCP RX checksum error, dropping pkt\n");
			valid_checksum = false;
		}

		b = rxqe->mbuf;
		new_b = mbuf_alloc(rxq->alloc);
		if (unlikely(!new_b)) {
			log_err("ixgbe: unable to allocate RX mbuf\n");
			goto out;
		}

		assert(mbuf_tailroom(new_b) >= IXGBE_MBUF_LEN);
		rxqe->mbuf = new_b;
		paddr = mbuf_data_phys(new_b);
		rxdp->read.hdr_addr = cpu_to_le32(paddr);
		rxdp->read.pkt_addr = cpu_to_le32(paddr);

		if (unlikely(!valid_checksum)) {
			log_info("ixgbe: dropping corrupted packet\n");
			mbuf_free(b);
		}

		/* fill in packet metadata */
		mbuf_put(b, le32_to_cpu(rxd.wb.upper.length));
		b->rss_hash = le32_to_cpu(rxd.wb.lower.hi_dword.rss);
		b->csum_type = CHECKSUM_TYPE_UNNECESSARY;

		pkts[nb_descs++] = b;
		rxq->head++;
	} while (nb_descs < nr);

out:
	/*
	 * We threshold updates to the RX tail register because when it
	 * is updated too frequently (e.g. when written to on multiple
	 * cores even through separate queues) PCI performance
	 * bottlenecks have been observed.
	 */
	if ((uint16_t)(rxq->len - (rxq->tail + 1 - rxq->head)) >=
	    IXGBE_RDT_THRESH) {
		rxq->tail = rxq->head + rxq->len - 1;

		/* inform HW that more descriptors have become available */
		IXGBE_PCI_REG_WRITE(rxq->rdt_reg_addr,
				    (rxq->tail & (rxq->len - 1)));
	}

	return nb_descs;
}

/**
 * ixgbe_dev_rx_queue_setup - prepares an RX queue
 * @dev: the ethernet device
 * @queue_idx: the queue number
 * @numa_node: the desired NUMA affinity, or -1 for no preference
 * @nb_desc: the number of descriptors to create for the ring
 * @a: packet buffers are allocated from this allocator
 *
 * Returns 0 if successful, otherwise failure.
 */
int ixgbe_dev_rx_queue_setup(struct rte_eth_dev *dev, int queue_idx,
			     int numa_node, uint16_t nb_desc,
			     struct mbuf_allocator *a)
{
	struct ixgbe_hw *hw;
	struct page *pg;
	struct rx_queue *rxq;
	void *page;
	int ret;

	hw = IXGBE_DEV_PRIVATE_TO_HW(dev->data->dev_private);

	/*
	 * The number of receive descriptors must not exceed hardware
	 * maximum and must be a multiple of IXGBE_ALIGN.
	 */
	if (((nb_desc * sizeof(union ixgbe_adv_rx_desc)) % IXGBE_ALIGN) != 0 ||
            nb_desc > IXGBE_MAX_RING_DESC || nb_desc < IXGBE_MIN_RING_DESC)
                return -EINVAL;

	/* The total size can't exceed PGSIZE_2MB */
	if(align_up(sizeof(struct rx_queue), IXGBE_ALIGN) +
	   (sizeof(union ixgbe_adv_rx_desc) + sizeof(struct rx_entry)) *
	   IXGBE_MAX_RING_DESC > PGSIZE_2MB)
		return -EINVAL;

	/* validate the allocator */
	if (a->head_len - a->reserve_len < IXGBE_MBUF_LEN)
		return -EINVAL;

	/*
	 * Additionally, for purely performance optimization reasons, we require
	 * the number of descriptors to be a power of 2.
	 */
	if (nb_desc & (nb_desc - 1))
		return -EINVAL;

	if (numa_node == -1) {
		pg = page_alloc(PGSIZE_2MB);
		if (!pg)
			return -ENOMEM;
	} else {
		pg = page_alloc_on_node(PGSIZE_2MB, numa_node);
		if (!pg)
			return -ENOMEM;
	}

	page = page_to_addr(pg);
	memset(page, 0, PGSIZE_2MB);
	rxq = (struct rx_queue *)page;
	rxq->ring = (union ixgbe_adv_rx_desc *)((uintptr_t)page +
		align_up(sizeof(struct rx_queue), IXGBE_ALIGN));
	rxq->ring_entries = (struct rx_entry *)((uintptr_t) rxq->ring +
		sizeof(union ixgbe_adv_rx_desc) * nb_desc);
	rxq->len = nb_desc;
	rxq->head = 0;
	rxq->tail = rxq->len - 1;
	rxq->ring_physaddr = pg->paddr +
		align_up(sizeof(struct rx_queue), IXGBE_ALIGN);
	rxq->alloc = a;
	rxq->queue_id = queue_idx;
	rxq->reg_idx = (uint16_t)((RTE_ETH_DEV_SRIOV(dev).active == 0) ?
		queue_idx : RTE_ETH_DEV_SRIOV(dev).def_pool_q_idx + queue_idx);

	if (hw->mac.type == ixgbe_mac_82599_vf) {
		rxq->rdt_reg_addr =
			IXGBE_PCI_REG_ADDR(hw, IXGBE_VFRDT(queue_idx));
		rxq->rdh_reg_addr =
			IXGBE_PCI_REG_ADDR(hw, IXGBE_VFRDH(queue_idx));
	} else {
		rxq->rdt_reg_addr =
			IXGBE_PCI_REG_ADDR(hw, IXGBE_RDT(rxq->reg_idx));
		rxq->rdh_reg_addr =
			IXGBE_PCI_REG_ADDR(hw, IXGBE_RDH(rxq->reg_idx));
	}

	rxq->erxq.recv = ixgbe_rx_recv;
	ret = ixgbe_alloc_rx_mbufs(rxq);
	if (ret)
		goto err;

	dev->data->rx_queues[queue_idx] = &rxq->erxq;
	return 0;

err:
	page_put(pg);
	return ret;
}

static int ixgbe_tx_reclaim(struct eth_tx_queue *tx)
{
	struct tx_queue *txq = eth_tx_queue_to_drv(tx);
	struct tx_entry *txe;
	volatile union ixgbe_adv_tx_desc *txdp;
	int idx = 0, nb_desc = 0;

	while ((uint16_t)(txq->head + idx) != txq->tail) {
		txe = &txq->ring_entries[(txq->head + idx) & (txq->len - 1)];

		if (!txe->mbuf) {
			idx++;
			continue;
		}

		txdp = &txq->ring[(txq->head + idx) & (txq->len - 1)];
		if (!(le32_to_cpu(txdp->wb.status) & IXGBE_TXD_STAT_DD))
			break;

		mbuf_free(txe->mbuf);
		txe->mbuf = NULL;
		idx++;
		nb_desc = idx;
	}

	txq->head += nb_desc;
	return (uint16_t)(txq->len + txq->head - txq->tail);
}

#define IP_HDR_LEN	20
/* ixgbe_tx_xmit_ctx - "transmit" context descriptor
 * 			tells NIC to load a new ctx into its memory
 * Currently assuming no no LSO.
 */
static int ixgbe_tx_xmit_ctx(struct tx_queue *txq, int txflags, int ctx_idx)
{
	volatile struct ixgbe_adv_tx_context_desc *txctxd;
	uint32_t type_tucmd_mlhl, mss_l4len_idx, vlan_macip_lens;

	/* Make sure enough space is available in the descriptor ring */
	if (unlikely((uint16_t) (txq->tail + 1 - txq->head) >= txq->len)) {
		ixgbe_tx_reclaim(&txq->etxq);
		if ((uint16_t) (txq->tail + 1 - txq->head) >= txq->len)
			return -EAGAIN;
	}

	/* Mark desc type as advanced context descriptor */
	type_tucmd_mlhl = IXGBE_ADVTXD_DTYP_CTXT | IXGBE_ADVTXD_DCMD_DEXT;

	/* Checksums */
	if (txflags & OLFLAG_IP_CHKSUM) {
		type_tucmd_mlhl |= IXGBE_ADVTXD_TUCMD_IPV4;
	}

	if (txflags & OLFLAG_TCP_CHKSUM) {
		type_tucmd_mlhl |= IXGBE_ADVTXD_TUCMD_L4T_TCP;
	}

	/* Set context idx. MSS and L4LEN ignored if no LSO */
	mss_l4len_idx = ctx_idx << IXGBE_ADVTXD_IDX_SHIFT;

	vlan_macip_lens = (ETH_HDR_LEN << IXGBE_ADVTXD_MACLEN_SHIFT) | IP_HDR_LEN;

	/* Put context desc on the desc ring */
	txctxd = (struct ixgbe_adv_tx_context_desc *) &txq->ring[txq->tail & (txq->len - 1)];

	txctxd->type_tucmd_mlhl = cpu_to_le32(type_tucmd_mlhl);
	txctxd->mss_l4len_idx   = cpu_to_le32(mss_l4len_idx);
	txctxd->seqnum_seed     = 0;
	txctxd->vlan_macip_lens = cpu_to_le32(vlan_macip_lens);

	/* Mark corresponding mbuf as NULL to allow desc reclaim */
	txq->ring_entries[txq->tail & (txq->len - 1)].mbuf = NULL;

	/* Used up a descriptor, advance tail */
	txq->tail++;
	IXGBE_PCI_REG_WRITE(txq->tdt_reg_addr,
				(txq->tail & (txq->len - 1)));

	/* Update flag info in software ctx_cache */
	txq->ctx_cache[ctx_idx].flags = txflags;

	return 0;
}

static int ixgbe_tx_xmit_one(struct tx_queue *txq, struct mbuf *mbuf)
{
	volatile union ixgbe_adv_tx_desc *txdp;
	uint32_t type_len, pay_len = mbuf_length(mbuf);
	uint32_t olinfo_status = 0;

	/*
	 * Make sure enough space is available in the descriptor ring
	 * NOTE: This should work correctly even with overflow...
	 */
	if (unlikely((uint16_t)(txq->tail + 1 - txq->head) >= txq->len)) {
		ixgbe_tx_reclaim(&txq->etxq);
		if ((uint16_t)(txq->tail + 1 - txq->head) >= txq->len)
			return -EAGAIN;
	}

	/*
	 * Check mbuf's offload flags
	 * If flags match context 0 on NIC (IP and TCP chksum), use context
	 * Otherwise, no context
	 */
	if ((mbuf->txflags & OLFLAG_IP_CHKSUM) &&
	    (mbuf->txflags & OLFLAG_TCP_CHKSUM)){
		olinfo_status |= IXGBE_ADVTXD_POPTS_IXSM;
		olinfo_status |= IXGBE_ADVTXD_POPTS_TXSM;
		olinfo_status |= IXGBE_ADVTXD_CC;
	}

	txq->ring_entries[(txq->tail) & (txq->len - 1)].mbuf = mbuf;
	txdp = &txq->ring[txq->tail & (txq->len - 1)];
	txdp->read.buffer_addr = cpu_to_le64(mbuf_data_phys(mbuf));

	type_len = (IXGBE_ADVTXD_DTYP_DATA |
		    IXGBE_ADVTXD_DCMD_IFCS |
		    IXGBE_ADVTXD_DCMD_DEXT |
		    IXGBE_ADVTXD_DCMD_EOP |
		    IXGBE_ADVTXD_DCMD_RS);
	type_len |= pay_len;

	txdp->read.cmd_type_len = cpu_to_le32(type_len);
	txdp->read.olinfo_status =
		cpu_to_le32(pay_len << IXGBE_ADVTXD_PAYLEN_SHIFT) |
		cpu_to_le32(olinfo_status);
	txq->tail++;

	return 0;
}

static int ixgbe_tx_xmit(struct eth_tx_queue *tx, int nr, struct mbuf **mbufs)
{
	struct tx_queue *txq = eth_tx_queue_to_drv(tx);
	int nb_pkts = 0;

	while (nb_pkts < nr) {
		if (ixgbe_tx_xmit_one(txq, mbufs[nb_pkts]))
			break;

		nb_pkts++;
	}

	if (nb_pkts)
		IXGBE_PCI_REG_WRITE(txq->tdt_reg_addr,
				    (txq->tail & (txq->len - 1)));

	return nb_pkts;
}

/**
 * ixgbe_dev_rx_queue_release - frees an RX queue
 * @rxq: the RX queue to free
 */
void ixgbe_dev_rx_queue_release(struct eth_rx_queue *erxq)
{
	struct rx_queue *rxq = eth_rx_queue_to_drv(erxq);

	ixgbe_clear_rx_queue(rxq);
	page_put(addr_to_page(rxq));
}

static void ixgbe_reset_tx_queue(struct tx_queue *txq)
{
	int i;

	for (i = 0; i < txq->len; i++) {
		txq->ring_entries[i].mbuf = NULL;
	}

	txq->head = 0;
	txq->tail = 0;

}

/**
 * ixgbe_dev_tx_queue_setup - prepares an RX queue
 * @dev: the ethernet device
 * @queue_idx: the queue number
 * @numa_node: the desired NUMA affinity, or -1 for no preference
 * @nb_desc: the number of descriptors to create for the ring
 *
 * Returns 0 if successful, otherwise failure.
 */

int ixgbe_dev_tx_queue_setup(struct rte_eth_dev *dev, int queue_idx,
			     int numa_node, uint16_t nb_desc)
{
	struct tx_queue *txq;
	struct ixgbe_hw *hw;
	void *page;
	struct page *pg;

	hw = IXGBE_DEV_PRIVATE_TO_HW(dev->data->dev_private);

	/*
	 * The number of receive descriptors must not exceed hardware
	 * maximum and must be a multiple of IXGBE_ALIGN.
	 */
	if (((nb_desc * sizeof(union ixgbe_adv_tx_desc)) % IXGBE_ALIGN) != 0 ||
            nb_desc > IXGBE_MAX_RING_DESC || nb_desc < IXGBE_MIN_RING_DESC)
                return -EINVAL;

	/* must fit within PGSIZE_2MB */
	if (align_up(sizeof(struct tx_queue), IXGBE_ALIGN) +
	    (sizeof(union ixgbe_adv_tx_desc) + sizeof(struct tx_entry)) *
	    IXGBE_MAX_RING_DESC > PGSIZE_2MB)
		return -EINVAL;

	/*
	 * Additionally, for purely software performance optimization reasons,
	 * we require the number of descriptors to be a power of 2.
	 */
	if (nb_desc & (nb_desc - 1))
		return -EINVAL;

	if (numa_node == -1) {
		pg = page_alloc(PGSIZE_2MB);
		if (!pg)
			return -ENOMEM;
	} else {
		pg = page_alloc_on_node(PGSIZE_2MB, numa_node);
		if (!pg)
			return -ENOMEM;
	}

	page = page_to_addr(pg);
	memset(page, 0, PGSIZE_2MB);
	txq = (struct tx_queue *)page;
	txq->ring = (union ixgbe_adv_tx_desc *) ((uintptr_t) page +
		align_up(sizeof(struct tx_queue), IXGBE_ALIGN));
	txq->ring_entries = (struct tx_entry *) ((uintptr_t) txq->ring +
		sizeof(union ixgbe_adv_tx_desc) * nb_desc);
	txq->len = nb_desc;
	txq->ring_physaddr = pg->paddr +
			     align_up(sizeof(struct tx_queue), IXGBE_ALIGN);
	txq->queue_id = queue_idx;
	txq->reg_idx = (uint16_t) ((RTE_ETH_DEV_SRIOV(dev).active == 0) ?
		queue_idx : RTE_ETH_DEV_SRIOV(dev).def_pool_q_idx + queue_idx);

	/*
	 * Modification to set VFTDT for virtual function if vf is detected
	 */
	if (hw->mac.type == ixgbe_mac_82599_vf)
		txq->tdt_reg_addr = IXGBE_PCI_REG_ADDR(hw, IXGBE_VFTDT(queue_idx));
	else
		txq->tdt_reg_addr = IXGBE_PCI_REG_ADDR(hw, IXGBE_TDT(txq->reg_idx));

	txq->etxq.reclaim = ixgbe_tx_reclaim;
	txq->etxq.xmit = ixgbe_tx_xmit;

	ixgbe_reset_tx_queue(txq);
	dev->data->tx_queues[queue_idx] = &txq->etxq;

	return 0;
}

/**
 * ixgbe_dev_tx_queue_release - frees a TX queue
 * @rxq: the RX queue to free
 */
void ixgbe_dev_tx_queue_release(struct eth_tx_queue *etxq)
{
	struct tx_queue *txq = eth_tx_queue_to_drv(etxq);
	page_put(addr_to_page(txq));
}


/**
 * Receive Side Scaling (RSS)
 * See section 7.1.2.8 in the following document:
 *     "Intel 82599 10 GbE Controller Datasheet" - Revision 2.1 October 2009
 *
 * Principles:
 * The source and destination IP addresses of the IP header and the source
 * and destination ports of TCP/UDP headers, if any, of received packets are
 * hashed against a configurable random key to compute a 32-bit RSS hash result.
 * The seven (7) LSBs of the 32-bit hash result are used as an index into a
 * 128-entry redirection table (RETA).  Each entry of the RETA provides a 3-bit
 * RSS output index which is used as the RX queue index where to store the
 * received packets.
 * The following output is supplied in the RX write-back descriptor:
 *     - 32-bit result of the Microsoft RSS hash function,
 *     - 4-bit RSS type field.
 */

/*
 * RSS random key supplied in section 7.1.2.8.3 of the Intel 82599 datasheet.
 * Used as the default key.
 */
static uint8_t rss_intel_key[40] = {
	0x6D, 0x5A, 0x56, 0xDA, 0x25, 0x5B, 0x0E, 0xC2,
	0x41, 0x67, 0x25, 0x3D, 0x43, 0xA3, 0x8F, 0xB0,
	0xD0, 0xCA, 0x2B, 0xCB, 0xAE, 0x7B, 0x30, 0xB4,
	0x77, 0xCB, 0x2D, 0xA3, 0x80, 0x30, 0xF2, 0x0C,
	0x6A, 0x42, 0xB7, 0x3B, 0xBE, 0xAC, 0x01, 0xFA,
};

static void
ixgbe_rss_disable(struct rte_eth_dev *dev)
{
	struct ixgbe_hw *hw;
	uint32_t mrqc;

	hw = IXGBE_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	mrqc = IXGBE_READ_REG(hw, IXGBE_MRQC);
	mrqc &= ~IXGBE_MRQC_RSSEN;
	IXGBE_WRITE_REG(hw, IXGBE_MRQC, mrqc);
}

static void
ixgbe_rss_configure(struct rte_eth_dev *dev)
{
	struct ixgbe_hw *hw;
	uint8_t *hash_key;
	uint32_t rss_key;
	uint32_t mrqc;
	uint32_t reta;
	uint16_t rss_hf;
	uint16_t i;
	uint16_t j;

	hw = IXGBE_DEV_PRIVATE_TO_HW(dev->data->dev_private);

	rss_hf = dev->data->dev_conf.rx_adv_conf.rss_conf.rss_hf;
	if (rss_hf == 0) { /* Disable RSS */
		ixgbe_rss_disable(dev);
		return;
	}
	hash_key = dev->data->dev_conf.rx_adv_conf.rss_conf.rss_key;
	if (hash_key == NULL)
		hash_key = rss_intel_key; /* Default hash key */

	/* Fill in RSS hash key */
	for (i = 0; i < 10; i++) {
		rss_key  = hash_key[(i * 4)];
		rss_key |= hash_key[(i * 4) + 1] << 8;
		rss_key |= hash_key[(i * 4) + 2] << 16;
		rss_key |= hash_key[(i * 4) + 3] << 24;
		IXGBE_WRITE_REG_ARRAY(hw, IXGBE_RSSRK(0), i, rss_key);
	}

	/* Fill in redirection table */
	reta = 0;
	for (i = 0, j = 0; i < 128; i++, j++) {
		if (j == dev->data->nb_rx_queues) j = 0;
		reta = (reta << 8) | j;
		if ((i & 3) == 3)
			IXGBE_WRITE_REG(hw, IXGBE_RETA(i >> 2), __bswap32(reta));
	}

	/* Set configured hashing functions in MRQC register */
	mrqc = IXGBE_MRQC_RSSEN; /* RSS enable */
	if (rss_hf & ETH_RSS_IPV4)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV4;
	if (rss_hf & ETH_RSS_IPV4_TCP)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV4_TCP;
	if (rss_hf & ETH_RSS_IPV6)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV6;
	if (rss_hf & ETH_RSS_IPV6_EX)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV6_EX;
	if (rss_hf & ETH_RSS_IPV6_TCP)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV6_TCP;
	if (rss_hf & ETH_RSS_IPV6_TCP_EX)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV6_EX_TCP;
	if (rss_hf & ETH_RSS_IPV4_UDP)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV4_UDP;
	if (rss_hf & ETH_RSS_IPV6_UDP)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV6_UDP;
	if (rss_hf & ETH_RSS_IPV6_UDP_EX)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV6_EX_UDP;
	IXGBE_WRITE_REG(hw, IXGBE_MRQC, mrqc);
}

#define NUM_VFTA_REGISTERS 128
#define NIC_RX_BUFFER_SIZE 0x200

static void
ixgbe_vmdq_dcb_configure(struct rte_eth_dev *dev)
{
	struct rte_eth_vmdq_dcb_conf *cfg;
	struct ixgbe_hw *hw;
	enum rte_eth_nb_pools num_pools;
	uint32_t mrqc, vt_ctl, queue_mapping, vlanctrl;
	uint16_t pbsize;
	uint8_t nb_tcs; /* number of traffic classes */
	int i;

	hw = IXGBE_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	cfg = &dev->data->dev_conf.rx_adv_conf.vmdq_dcb_conf;
	num_pools = cfg->nb_queue_pools;
	/* Check we have a valid number of pools */
	if (num_pools != ETH_16_POOLS && num_pools != ETH_32_POOLS) {
		ixgbe_rss_disable(dev);
		return;
	}
	/* 16 pools -> 8 traffic classes, 32 pools -> 4 traffic classes */
	nb_tcs = (uint8_t)(ETH_VMDQ_DCB_NUM_QUEUES / (int)num_pools);

	/*
	 * RXPBSIZE
	 * split rx buffer up into sections, each for 1 traffic class
	 */
	pbsize = (uint16_t)(NIC_RX_BUFFER_SIZE / nb_tcs);
	for (i = 0 ; i < nb_tcs; i++) {
		uint32_t rxpbsize = IXGBE_READ_REG(hw, IXGBE_RXPBSIZE(i));
		rxpbsize &= (~(0x3FF << IXGBE_RXPBSIZE_SHIFT));
		/* clear 10 bits. */
		rxpbsize |= (pbsize << IXGBE_RXPBSIZE_SHIFT); /* set value */
		IXGBE_WRITE_REG(hw, IXGBE_RXPBSIZE(i), rxpbsize);
	}
	/* zero alloc all unused TCs */
	for (i = nb_tcs; i < ETH_DCB_NUM_USER_PRIORITIES; i++) {
		uint32_t rxpbsize = IXGBE_READ_REG(hw, IXGBE_RXPBSIZE(i));
		rxpbsize &= (~( 0x3FF << IXGBE_RXPBSIZE_SHIFT ));
		/* clear 10 bits. */
		IXGBE_WRITE_REG(hw, IXGBE_RXPBSIZE(i), rxpbsize);
	}

	/* MRQC: enable vmdq and dcb */
	mrqc = ((num_pools == ETH_16_POOLS) ? \
		IXGBE_MRQC_VMDQRT8TCEN : IXGBE_MRQC_VMDQRT4TCEN );
	IXGBE_WRITE_REG(hw, IXGBE_MRQC, mrqc);

	/* PFVTCTL: turn on virtualisation and set the default pool */
	vt_ctl = IXGBE_VT_CTL_VT_ENABLE | IXGBE_VT_CTL_REPLEN;
	if (cfg->enable_default_pool) {
		vt_ctl |= (cfg->default_pool << IXGBE_VT_CTL_POOL_SHIFT);
	} else {
		vt_ctl |= IXGBE_VT_CTL_DIS_DEFPL;
	}

	IXGBE_WRITE_REG(hw, IXGBE_VT_CTL, vt_ctl);

	/* RTRUP2TC: mapping user priorities to traffic classes (TCs) */
	queue_mapping = 0;
	for (i = 0; i < ETH_DCB_NUM_USER_PRIORITIES; i++)
		/*
		 * mapping is done with 3 bits per priority,
		 * so shift by i*3 each time
		 */
		queue_mapping |= ((cfg->dcb_queue[i] & 0x07) << (i * 3));

	IXGBE_WRITE_REG(hw, IXGBE_RTRUP2TC, queue_mapping);

	/* RTRPCS: DCB related */
	IXGBE_WRITE_REG(hw, IXGBE_RTRPCS, IXGBE_RMCS_RRM);

	/* VLNCTRL: enable vlan filtering and allow all vlan tags through */
	vlanctrl = IXGBE_READ_REG(hw, IXGBE_VLNCTRL);
	vlanctrl |= IXGBE_VLNCTRL_VFE ; /* enable vlan filters */
	IXGBE_WRITE_REG(hw, IXGBE_VLNCTRL, vlanctrl);

	/* VFTA - enable all vlan filters */
	for (i = 0; i < NUM_VFTA_REGISTERS; i++) {
		IXGBE_WRITE_REG(hw, IXGBE_VFTA(i), 0xFFFFFFFF);
	}

	/* VFRE: pool enabling for receive - 16 or 32 */
	IXGBE_WRITE_REG(hw, IXGBE_VFRE(0), \
			num_pools == ETH_16_POOLS ? 0xFFFF : 0xFFFFFFFF);

	/*
	 * MPSAR - allow pools to read specific mac addresses
	 * In this case, all pools should be able to read from mac addr 0
	 */
	IXGBE_WRITE_REG(hw, IXGBE_MPSAR_LO(0), 0xFFFFFFFF);
	IXGBE_WRITE_REG(hw, IXGBE_MPSAR_HI(0), 0xFFFFFFFF);

	/* PFVLVF, PFVLVFB: set up filters for vlan tags as configured */
	for (i = 0; i < cfg->nb_pool_maps; i++) {
		/* set vlan id in VF register and set the valid bit */
		IXGBE_WRITE_REG(hw, IXGBE_VLVF(i), (IXGBE_VLVF_VIEN | \
				(cfg->pool_map[i].vlan_id & 0xFFF)));
		/*
		 * Put the allowed pools in VFB reg. As we only have 16 or 32
		 * pools, we only need to use the first half of the register
		 * i.e. bits 0-31
		 */
		IXGBE_WRITE_REG(hw, IXGBE_VLVFB(i*2), cfg->pool_map[i].pools);
	}
}

/**
 * ixgbe_dcb_config_tx_hw_config - Configure general DCB TX parameters
 * @hw: pointer to hardware structure
 * @dcb_config: pointer to ixgbe_dcb_config structure
 */
static void 
ixgbe_dcb_tx_hw_config(struct ixgbe_hw *hw,
               struct ixgbe_dcb_config *dcb_config)
{
	uint32_t reg;
	uint32_t q;
	
	PMD_INIT_FUNC_TRACE();
	if (hw->mac.type != ixgbe_mac_82598EB) {
		/* Disable the Tx desc arbiter so that MTQC can be changed */
		reg = IXGBE_READ_REG(hw, IXGBE_RTTDCS);
		reg |= IXGBE_RTTDCS_ARBDIS;
		IXGBE_WRITE_REG(hw, IXGBE_RTTDCS, reg);

		/* Enable DCB for Tx with 8 TCs */
		if (dcb_config->num_tcs.pg_tcs == 8) {
			reg = IXGBE_MTQC_RT_ENA | IXGBE_MTQC_8TC_8TQ;
		}
		else {
			reg = IXGBE_MTQC_RT_ENA | IXGBE_MTQC_4TC_4TQ;
		}
		if (dcb_config->vt_mode)
	            reg |= IXGBE_MTQC_VT_ENA;
		IXGBE_WRITE_REG(hw, IXGBE_MTQC, reg);

		/* Disable drop for all queues */
		for (q = 0; q < 128; q++)
			IXGBE_WRITE_REG(hw, IXGBE_QDE,
	             (IXGBE_QDE_WRITE | (q << IXGBE_QDE_IDX_SHIFT)));

		/* Enable the Tx desc arbiter */
		reg = IXGBE_READ_REG(hw, IXGBE_RTTDCS);
		reg &= ~IXGBE_RTTDCS_ARBDIS;
		IXGBE_WRITE_REG(hw, IXGBE_RTTDCS, reg);

		/* Enable Security TX Buffer IFG for DCB */
		reg = IXGBE_READ_REG(hw, IXGBE_SECTXMINIFG);
		reg |= IXGBE_SECTX_DCB;
		IXGBE_WRITE_REG(hw, IXGBE_SECTXMINIFG, reg);
	}
	return;
}

/**
 * ixgbe_vmdq_dcb_hw_tx_config - Configure general VMDQ+DCB TX parameters
 * @dev: pointer to rte_eth_dev structure
 * @dcb_config: pointer to ixgbe_dcb_config structure
 */
static void
ixgbe_vmdq_dcb_hw_tx_config(struct rte_eth_dev *dev,
			struct ixgbe_dcb_config *dcb_config)
{
	struct rte_eth_vmdq_dcb_tx_conf *vmdq_tx_conf =
			&dev->data->dev_conf.tx_adv_conf.vmdq_dcb_tx_conf;
	struct ixgbe_hw *hw = 
			IXGBE_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	
	PMD_INIT_FUNC_TRACE();
	if (hw->mac.type != ixgbe_mac_82598EB) 	
		/*PF VF Transmit Enable*/
		IXGBE_WRITE_REG(hw, IXGBE_VFTE(0),
			vmdq_tx_conf->nb_queue_pools == ETH_16_POOLS ? 0xFFFF : 0xFFFFFFFF);
    
	/*Configure general DCB TX parameters*/
	ixgbe_dcb_tx_hw_config(hw,dcb_config);
	return;
}

static void 
ixgbe_vmdq_dcb_rx_config(struct rte_eth_dev *dev,
                        struct ixgbe_dcb_config *dcb_config)
{
	struct rte_eth_vmdq_dcb_conf *vmdq_rx_conf =
			&dev->data->dev_conf.rx_adv_conf.vmdq_dcb_conf;
	struct ixgbe_dcb_tc_config *tc;
	uint8_t i,j;

	/* convert rte_eth_conf.rx_adv_conf to struct ixgbe_dcb_config */
	if (vmdq_rx_conf->nb_queue_pools == ETH_16_POOLS ) {
		dcb_config->num_tcs.pg_tcs = ETH_8_TCS;
		dcb_config->num_tcs.pfc_tcs = ETH_8_TCS;
	}
	else {
		dcb_config->num_tcs.pg_tcs = ETH_4_TCS;
		dcb_config->num_tcs.pfc_tcs = ETH_4_TCS;
	}
	/* User Priority to Traffic Class mapping */
	for (i = 0; i < ETH_DCB_NUM_USER_PRIORITIES; i++) {
		j = vmdq_rx_conf->dcb_queue[i];
		tc = &dcb_config->tc_config[j];
		tc->path[IXGBE_DCB_RX_CONFIG].up_to_tc_bitmap =
						(uint8_t)(1 << j);
	}
}

static void 
ixgbe_dcb_vt_tx_config(struct rte_eth_dev *dev,
                        struct ixgbe_dcb_config *dcb_config)
{ 
	struct rte_eth_vmdq_dcb_tx_conf *vmdq_tx_conf =
			&dev->data->dev_conf.tx_adv_conf.vmdq_dcb_tx_conf;
	struct ixgbe_dcb_tc_config *tc;
	uint8_t i,j;
	
	/* convert rte_eth_conf.rx_adv_conf to struct ixgbe_dcb_config */
	if (vmdq_tx_conf->nb_queue_pools == ETH_16_POOLS ) {
		dcb_config->num_tcs.pg_tcs = ETH_8_TCS;
		dcb_config->num_tcs.pfc_tcs = ETH_8_TCS;
	}
	else {
		dcb_config->num_tcs.pg_tcs = ETH_4_TCS;
		dcb_config->num_tcs.pfc_tcs = ETH_4_TCS;
	}

	/* User Priority to Traffic Class mapping */
	for (i = 0; i < ETH_DCB_NUM_USER_PRIORITIES; i++) {
		j = vmdq_tx_conf->dcb_queue[i];
		tc = &dcb_config->tc_config[j];
		tc->path[IXGBE_DCB_TX_CONFIG].up_to_tc_bitmap =
						(uint8_t)(1 << j);
	}
	return;
}

static void 
ixgbe_dcb_rx_config(struct rte_eth_dev *dev,
		struct ixgbe_dcb_config *dcb_config)
{
	struct rte_eth_dcb_rx_conf *rx_conf =
			&dev->data->dev_conf.rx_adv_conf.dcb_rx_conf;
	struct ixgbe_dcb_tc_config *tc;
	uint8_t i,j;

	dcb_config->num_tcs.pg_tcs = (uint8_t)rx_conf->nb_tcs;
	dcb_config->num_tcs.pfc_tcs = (uint8_t)rx_conf->nb_tcs;
	
	/* User Priority to Traffic Class mapping */ 
	for (i = 0; i < ETH_DCB_NUM_USER_PRIORITIES; i++) {
		j = rx_conf->dcb_queue[i];
		tc = &dcb_config->tc_config[j];
		tc->path[IXGBE_DCB_RX_CONFIG].up_to_tc_bitmap =
						(uint8_t)(1 << j);
	}
}

static void 
ixgbe_dcb_tx_config(struct rte_eth_dev *dev,
		struct ixgbe_dcb_config *dcb_config)
{
	struct rte_eth_dcb_tx_conf *tx_conf =
			&dev->data->dev_conf.tx_adv_conf.dcb_tx_conf;
	struct ixgbe_dcb_tc_config *tc;
	uint8_t i,j;

	dcb_config->num_tcs.pg_tcs = (uint8_t)tx_conf->nb_tcs;
	dcb_config->num_tcs.pfc_tcs = (uint8_t)tx_conf->nb_tcs;
    
	/* User Priority to Traffic Class mapping */ 
	for (i = 0; i < ETH_DCB_NUM_USER_PRIORITIES; i++) {
		j = tx_conf->dcb_queue[i];
		tc = &dcb_config->tc_config[j];
		tc->path[IXGBE_DCB_TX_CONFIG].up_to_tc_bitmap =
						(uint8_t)(1 << j);
	}
}

/**
 * ixgbe_dcb_rx_hw_config - Configure general DCB RX HW parameters
 * @hw: pointer to hardware structure
 * @dcb_config: pointer to ixgbe_dcb_config structure
 */
static void
ixgbe_dcb_rx_hw_config(struct ixgbe_hw *hw,
               struct ixgbe_dcb_config *dcb_config)
{
	uint32_t reg;
	uint32_t vlanctrl;
	uint8_t i;

	PMD_INIT_FUNC_TRACE();
	/*
	 * Disable the arbiter before changing parameters
	 * (always enable recycle mode; WSP)
	 */
	reg = IXGBE_RTRPCS_RRM | IXGBE_RTRPCS_RAC | IXGBE_RTRPCS_ARBDIS;
	IXGBE_WRITE_REG(hw, IXGBE_RTRPCS, reg);

	if (hw->mac.type != ixgbe_mac_82598EB) {
		reg = IXGBE_READ_REG(hw, IXGBE_MRQC);
		if (dcb_config->num_tcs.pg_tcs == 4) {
			if (dcb_config->vt_mode)
				reg = (reg & ~IXGBE_MRQC_MRQE_MASK) |
					IXGBE_MRQC_VMDQRT4TCEN;
			else {
				IXGBE_WRITE_REG(hw, IXGBE_VT_CTL, 0);
				reg = (reg & ~IXGBE_MRQC_MRQE_MASK) |
					IXGBE_MRQC_RT4TCEN;
			}
		}
		if (dcb_config->num_tcs.pg_tcs == 8) {
			if (dcb_config->vt_mode)
				reg = (reg & ~IXGBE_MRQC_MRQE_MASK) |
					IXGBE_MRQC_VMDQRT8TCEN;
			else {
				IXGBE_WRITE_REG(hw, IXGBE_VT_CTL, 0);
				reg = (reg & ~IXGBE_MRQC_MRQE_MASK) |
					IXGBE_MRQC_RT8TCEN;
			}
		}

		IXGBE_WRITE_REG(hw, IXGBE_MRQC, reg);
	}

	/* VLNCTRL: enable vlan filtering and allow all vlan tags through */
	vlanctrl = IXGBE_READ_REG(hw, IXGBE_VLNCTRL);
	vlanctrl |= IXGBE_VLNCTRL_VFE ; /* enable vlan filters */
	IXGBE_WRITE_REG(hw, IXGBE_VLNCTRL, vlanctrl);
 
	/* VFTA - enable all vlan filters */
	for (i = 0; i < NUM_VFTA_REGISTERS; i++) {
		IXGBE_WRITE_REG(hw, IXGBE_VFTA(i), 0xFFFFFFFF);
	}

	/*
	 * Configure Rx packet plane (recycle mode; WSP) and
	 * enable arbiter
	 */
	reg = IXGBE_RTRPCS_RRM | IXGBE_RTRPCS_RAC;
	IXGBE_WRITE_REG(hw, IXGBE_RTRPCS, reg);
 
	return;
}

static void 
ixgbe_dcb_hw_arbite_rx_config(struct ixgbe_hw *hw, uint16_t *refill,
			uint16_t *max,uint8_t *bwg_id, uint8_t *tsa, uint8_t *map)
{
	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		ixgbe_dcb_config_rx_arbiter_82598(hw, refill, max, tsa);
		break;
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
		ixgbe_dcb_config_rx_arbiter_82599(hw, refill, max, bwg_id,
						  tsa, map);
		break;
	default:
		break;
	}
}

static void 
ixgbe_dcb_hw_arbite_tx_config(struct ixgbe_hw *hw, uint16_t *refill, uint16_t *max,
			    uint8_t *bwg_id, uint8_t *tsa, uint8_t *map)
{
	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		ixgbe_dcb_config_tx_desc_arbiter_82598(hw, refill, max, bwg_id,tsa);
		ixgbe_dcb_config_tx_data_arbiter_82598(hw, refill, max, bwg_id,tsa);
		break;
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
		ixgbe_dcb_config_tx_desc_arbiter_82599(hw, refill, max, bwg_id,tsa);
		ixgbe_dcb_config_tx_data_arbiter_82599(hw, refill, max, bwg_id,tsa, map);
		break;
	default:
		break;
	}
}

#define DCB_RX_CONFIG  1
#define DCB_TX_CONFIG  1
#define DCB_TX_PB      1024
/**
 * ixgbe_dcb_hw_configure - Enable DCB and configure 
 * general DCB in VT mode and non-VT mode parameters
 * @dev: pointer to rte_eth_dev structure
 * @dcb_config: pointer to ixgbe_dcb_config structure
 */
static int
ixgbe_dcb_hw_configure(struct rte_eth_dev *dev,
			struct ixgbe_dcb_config *dcb_config)
{
	int     ret = 0;
	uint8_t i,pfc_en,nb_tcs;
	uint16_t pbsize;
	uint8_t config_dcb_rx = 0;
	uint8_t config_dcb_tx = 0;
	uint8_t tsa[IXGBE_DCB_MAX_TRAFFIC_CLASS] = {0};
	uint8_t bwgid[IXGBE_DCB_MAX_TRAFFIC_CLASS] = {0};
	uint16_t refill[IXGBE_DCB_MAX_TRAFFIC_CLASS] = {0};
	uint16_t max[IXGBE_DCB_MAX_TRAFFIC_CLASS] = {0};
	uint8_t map[IXGBE_DCB_MAX_TRAFFIC_CLASS] = {0};
	struct ixgbe_dcb_tc_config *tc;
	uint32_t max_frame = dev->data->max_frame_size;
	struct ixgbe_hw *hw = 
			IXGBE_DEV_PRIVATE_TO_HW(dev->data->dev_private);

	switch(dev->data->dev_conf.rxmode.mq_mode){
	case ETH_MQ_RX_VMDQ_DCB:
		dcb_config->vt_mode = true;
		if (hw->mac.type != ixgbe_mac_82598EB) {
			config_dcb_rx = DCB_RX_CONFIG;
			/*
			 *get dcb and VT rx configuration parameters 
			 *from rte_eth_conf
			 */
			ixgbe_vmdq_dcb_rx_config(dev,dcb_config);
			/*Configure general VMDQ and DCB RX parameters*/
			ixgbe_vmdq_dcb_configure(dev);
		}
		break;
	case ETH_MQ_RX_DCB:
		dcb_config->vt_mode = false;
		config_dcb_rx = DCB_RX_CONFIG;
		/* Get dcb TX configuration parameters from rte_eth_conf */
		ixgbe_dcb_rx_config(dev,dcb_config);
		/*Configure general DCB RX parameters*/
		ixgbe_dcb_rx_hw_config(hw, dcb_config);
		break;
	default:
		PMD_INIT_LOG(ERR, "Incorrect DCB RX mode configuration\n");
		break;
	}
	switch (dev->data->dev_conf.txmode.mq_mode) {
	case ETH_MQ_TX_VMDQ_DCB:
		dcb_config->vt_mode = true;
		config_dcb_tx = DCB_TX_CONFIG;
		/* get DCB and VT TX configuration parameters from rte_eth_conf */
		ixgbe_dcb_vt_tx_config(dev,dcb_config);
		/*Configure general VMDQ and DCB TX parameters*/
		ixgbe_vmdq_dcb_hw_tx_config(dev,dcb_config);
		break;

	case ETH_MQ_TX_DCB:
		dcb_config->vt_mode = false;
		config_dcb_tx = DCB_TX_CONFIG;
		/*get DCB TX configuration parameters from rte_eth_conf*/
		ixgbe_dcb_tx_config(dev,dcb_config);
		/*Configure general DCB TX parameters*/
		ixgbe_dcb_tx_hw_config(hw, dcb_config);
		break;
	default:
		PMD_INIT_LOG(ERR, "Incorrect DCB TX mode configuration\n");
		break;
	}

	nb_tcs = dcb_config->num_tcs.pfc_tcs;
	/* Unpack map */
	ixgbe_dcb_unpack_map_cee(dcb_config, IXGBE_DCB_RX_CONFIG, map);
	if(nb_tcs == ETH_4_TCS) {
		/* Avoid un-configured priority mapping to TC0 */
		uint8_t j = 4;
		uint8_t mask = 0xFF;
		for (i = 0; i < ETH_DCB_NUM_USER_PRIORITIES - 4; i++) 
			mask = (uint8_t)(mask & (~ (1 << map[i])));
		for (i = 0; mask && (i < IXGBE_DCB_MAX_TRAFFIC_CLASS); i++) {
			if ((mask & 0x1) && (j < ETH_DCB_NUM_USER_PRIORITIES))
				map[j++] = i;
			mask >>= 1;
		}
		/* Re-configure 4 TCs BW */
		for (i = 0; i < nb_tcs; i++) {
			tc = &dcb_config->tc_config[i];
			tc->path[IXGBE_DCB_TX_CONFIG].bwg_percent =
						(uint8_t)(100 / nb_tcs);
			tc->path[IXGBE_DCB_RX_CONFIG].bwg_percent =
						(uint8_t)(100 / nb_tcs);
		}
		for (; i < IXGBE_DCB_MAX_TRAFFIC_CLASS; i++) {
			tc = &dcb_config->tc_config[i];
			tc->path[IXGBE_DCB_TX_CONFIG].bwg_percent = 0;
			tc->path[IXGBE_DCB_RX_CONFIG].bwg_percent = 0;
		}
	}

	if(config_dcb_rx) {
		/* Set RX buffer size */
		pbsize = (uint16_t)(NIC_RX_BUFFER_SIZE / nb_tcs);
		uint32_t rxpbsize = pbsize << IXGBE_RXPBSIZE_SHIFT;
		for (i = 0 ; i < nb_tcs; i++) {
			IXGBE_WRITE_REG(hw, IXGBE_RXPBSIZE(i), rxpbsize);
		}
		/* zero alloc all unused TCs */
		for (; i < ETH_DCB_NUM_USER_PRIORITIES; i++) {
			IXGBE_WRITE_REG(hw, IXGBE_RXPBSIZE(i), 0);
		}
	}
	if(config_dcb_tx) {
		/* Only support an equally distributed Tx packet buffer strategy. */
		uint32_t txpktsize = IXGBE_TXPBSIZE_MAX / nb_tcs;
		uint32_t txpbthresh = (txpktsize / DCB_TX_PB) - IXGBE_TXPKT_SIZE_MAX;
		for (i = 0; i < nb_tcs; i++) {
			IXGBE_WRITE_REG(hw, IXGBE_TXPBSIZE(i), txpktsize);
			IXGBE_WRITE_REG(hw, IXGBE_TXPBTHRESH(i), txpbthresh);
		}
		/* Clear unused TCs, if any, to zero buffer size*/
		for (; i < ETH_DCB_NUM_USER_PRIORITIES; i++) {
			IXGBE_WRITE_REG(hw, IXGBE_TXPBSIZE(i), 0);
			IXGBE_WRITE_REG(hw, IXGBE_TXPBTHRESH(i), 0);
		}
	}

	/*Calculates traffic class credits*/
	ixgbe_dcb_calculate_tc_credits_cee(hw, dcb_config,max_frame,
				IXGBE_DCB_TX_CONFIG);
	ixgbe_dcb_calculate_tc_credits_cee(hw, dcb_config,max_frame,
				IXGBE_DCB_RX_CONFIG);

	if(config_dcb_rx) {
		/* Unpack CEE standard containers */
		ixgbe_dcb_unpack_refill_cee(dcb_config, IXGBE_DCB_RX_CONFIG, refill);
		ixgbe_dcb_unpack_max_cee(dcb_config, max);
		ixgbe_dcb_unpack_bwgid_cee(dcb_config, IXGBE_DCB_RX_CONFIG, bwgid);
		ixgbe_dcb_unpack_tsa_cee(dcb_config, IXGBE_DCB_RX_CONFIG, tsa);
		/* Configure PG(ETS) RX */
		ixgbe_dcb_hw_arbite_rx_config(hw,refill,max,bwgid,tsa,map);
	}

	if(config_dcb_tx) {
		/* Unpack CEE standard containers */
		ixgbe_dcb_unpack_refill_cee(dcb_config, IXGBE_DCB_TX_CONFIG, refill);
		ixgbe_dcb_unpack_max_cee(dcb_config, max);
		ixgbe_dcb_unpack_bwgid_cee(dcb_config, IXGBE_DCB_TX_CONFIG, bwgid);
		ixgbe_dcb_unpack_tsa_cee(dcb_config, IXGBE_DCB_TX_CONFIG, tsa);
		/* Configure PG(ETS) TX */
		ixgbe_dcb_hw_arbite_tx_config(hw,refill,max,bwgid,tsa,map);
	}

	/*Configure queue statistics registers*/
	ixgbe_dcb_config_tc_stats_82599(hw, dcb_config);

	/* Check if the PFC is supported */
	if(dev->data->dev_conf.dcb_capability_en & ETH_DCB_PFC_SUPPORT) {
		pbsize = (uint16_t) (NIC_RX_BUFFER_SIZE / nb_tcs);
		for (i = 0; i < nb_tcs; i++) {
			/*
			* If the TC count is 8,and the default high_water is 48,
			* the low_water is 16 as default.
			*/
			hw->fc.high_water[i] = (pbsize * 3 ) / 4;
			hw->fc.low_water[i] = pbsize / 4;
			/* Enable pfc for this TC */
			tc = &dcb_config->tc_config[i];
			tc->pfc = ixgbe_dcb_pfc_enabled;
		}
		ixgbe_dcb_unpack_pfc_cee(dcb_config, map, &pfc_en);
		if(dcb_config->num_tcs.pfc_tcs == ETH_4_TCS)
			pfc_en &= 0x0F;
		ret = ixgbe_dcb_config_pfc(hw, pfc_en, map);
	}

	return ret;
}

/**
 * ixgbe_configure_dcb - configure DCB HW
 * @dev: the ethernet device
 */
void ixgbe_configure_dcb(struct rte_eth_dev *dev)
{
        struct ixgbe_dcb_config *dcb_cfg =
                        IXGBE_DEV_PRIVATE_TO_DCB_CFG(dev->data->dev_private);
        struct rte_eth_conf *dev_conf = &(dev->data->dev_conf);

        /* check support mq_mode for DCB */
        if ((dev_conf->rxmode.mq_mode != ETH_MQ_RX_VMDQ_DCB) &&
            (dev_conf->rxmode.mq_mode != ETH_MQ_RX_DCB))
                return;

        if (dev->data->nb_rx_queues != ETH_DCB_NUM_QUEUES)
                return;

        /** Configure DCB hardware **/
        ixgbe_dcb_hw_configure(dev,dcb_cfg);

        return;
}

/*
 * VMDq only support for 10 GbE NIC.
 */
static void
ixgbe_vmdq_rx_hw_configure(struct rte_eth_dev *dev)
{
	struct rte_eth_vmdq_rx_conf *cfg;
	struct ixgbe_hw *hw;
	enum rte_eth_nb_pools num_pools;
	uint32_t mrqc, vt_ctl, vlanctrl;
	int i;

	PMD_INIT_FUNC_TRACE();
	hw = IXGBE_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	cfg = &dev->data->dev_conf.rx_adv_conf.vmdq_rx_conf;
	num_pools = cfg->nb_queue_pools;

	ixgbe_rss_disable(dev);

	/* MRQC: enable vmdq */
	mrqc = IXGBE_MRQC_VMDQEN;
	IXGBE_WRITE_REG(hw, IXGBE_MRQC, mrqc);

	/* PFVTCTL: turn on virtualisation and set the default pool */
	vt_ctl = IXGBE_VT_CTL_VT_ENABLE | IXGBE_VT_CTL_REPLEN;
	if (cfg->enable_default_pool)
		vt_ctl |= (cfg->default_pool << IXGBE_VT_CTL_POOL_SHIFT);
	else
		vt_ctl |= IXGBE_VT_CTL_DIS_DEFPL;

	IXGBE_WRITE_REG(hw, IXGBE_VT_CTL, vt_ctl);

	/* VLNCTRL: enable vlan filtering and allow all vlan tags through */
	vlanctrl = IXGBE_READ_REG(hw, IXGBE_VLNCTRL);
	vlanctrl |= IXGBE_VLNCTRL_VFE ; /* enable vlan filters */
	IXGBE_WRITE_REG(hw, IXGBE_VLNCTRL, vlanctrl);

	/* VFTA - enable all vlan filters */
	for (i = 0; i < NUM_VFTA_REGISTERS; i++) 
		IXGBE_WRITE_REG(hw, IXGBE_VFTA(i), UINT32_MAX);

	/* VFRE: pool enabling for receive - 64 */
	IXGBE_WRITE_REG(hw, IXGBE_VFRE(0), UINT32_MAX);
	if (num_pools == ETH_64_POOLS)
		IXGBE_WRITE_REG(hw, IXGBE_VFRE(1), UINT32_MAX);

	/*
	 * MPSAR - allow pools to read specific mac addresses
	 * In this case, all pools should be able to read from mac addr 0
	 */
	IXGBE_WRITE_REG(hw, IXGBE_MPSAR_LO(0), UINT32_MAX);
	IXGBE_WRITE_REG(hw, IXGBE_MPSAR_HI(0), UINT32_MAX);

	/* PFVLVF, PFVLVFB: set up filters for vlan tags as configured */
	for (i = 0; i < cfg->nb_pool_maps; i++) {
		/* set vlan id in VF register and set the valid bit */
		IXGBE_WRITE_REG(hw, IXGBE_VLVF(i), (IXGBE_VLVF_VIEN | \
				(cfg->pool_map[i].vlan_id & IXGBE_RXD_VLAN_ID_MASK)));
		/*
		 * Put the allowed pools in VFB reg. As we only have 16 or 64
		 * pools, we only need to use the first half of the register
		 * i.e. bits 0-31
		 */
		if (((cfg->pool_map[i].pools >> 32) & UINT32_MAX) == 0) 
			IXGBE_WRITE_REG(hw, IXGBE_VLVFB(i*2), \
					(cfg->pool_map[i].pools & UINT32_MAX));
		else
			IXGBE_WRITE_REG(hw, IXGBE_VLVFB((i*2+1)), \
					((cfg->pool_map[i].pools >> 32) \
					& UINT32_MAX));

	}

	IXGBE_WRITE_FLUSH(hw);
}

static int
ixgbe_dev_mq_rx_configure(struct rte_eth_dev *dev)
{
	struct ixgbe_hw *hw = 
		IXGBE_DEV_PRIVATE_TO_HW(dev->data->dev_private);

	if (hw->mac.type == ixgbe_mac_82598EB)
		return 0;

	if (RTE_ETH_DEV_SRIOV(dev).active == 0) {
		/* 
	 	 * SRIOV inactive scheme
		 * any DCB/RSS w/o VMDq multi-queue setting
		 */
		switch (dev->data->dev_conf.rxmode.mq_mode) {
			case ETH_MQ_RX_RSS:
				ixgbe_rss_configure(dev);
				break;

			case ETH_MQ_RX_VMDQ_DCB:
				ixgbe_vmdq_dcb_configure(dev);
				break;
	
			case ETH_MQ_RX_VMDQ_ONLY:
				ixgbe_vmdq_rx_hw_configure(dev);
				break;
			
			case ETH_MQ_RX_NONE:
				/* if mq_mode is none, disable rss mode.*/
			default: ixgbe_rss_disable(dev);
		}
	} else {
		switch (RTE_ETH_DEV_SRIOV(dev).active) {
		/*
		 * SRIOV active scheme
		 * FIXME if support DCB/RSS together with VMDq & SRIOV
		 */
		case ETH_64_POOLS:
			IXGBE_WRITE_REG(hw, IXGBE_MRQC, IXGBE_MRQC_VMDQEN);
			break;

		case ETH_32_POOLS:
			IXGBE_WRITE_REG(hw, IXGBE_MRQC, IXGBE_MRQC_VMDQRT4TCEN);
			break;
		
		case ETH_16_POOLS:
			IXGBE_WRITE_REG(hw, IXGBE_MRQC, IXGBE_MRQC_VMDQRT8TCEN);
			break;
		default:
			log_err("ixgbe: invalid pool number in IOV mode\n");
		}
	}

	return 0;
}

/**
 * ixgbe_dev_rx_init - initializes the RX subsystem
 * @dev: the ethernet device
 *
 * Returns 0 if successful, otherwise failure.
 */
int ixgbe_dev_rx_init(struct rte_eth_dev *dev)
{
	int i;
	struct ixgbe_hw *hw;
	uint32_t rxctrl, fctrl, hlreg0, maxfrs, rxcsum, rdrxctl;

	hw = IXGBE_DEV_PRIVATE_TO_HW(dev->data->dev_private);

	/*
	 * Make sure receives are disable while setting
	 * up the RX context (registers, descriptor rings, etc.).
	 */
	rxctrl = IXGBE_READ_REG(hw, IXGBE_RXCTRL);
	IXGBE_WRITE_REG(hw, IXGBE_RXCTRL, rxctrl & ~IXGBE_RXCTRL_RXEN);

	/* Enable receipt of broadcasted frames */
	fctrl = IXGBE_READ_REG(hw, IXGBE_FCTRL);
	fctrl |= IXGBE_FCTRL_BAM;
	fctrl |= IXGBE_FCTRL_DPF;
	fctrl |= IXGBE_FCTRL_PMCF;
	IXGBE_WRITE_REG(hw, IXGBE_FCTRL, fctrl);

	/* Configure CRC stripping */
	hlreg0 = IXGBE_READ_REG(hw, IXGBE_HLREG0);
	if (dev->data->dev_conf.rxmode.hw_strip_crc)
		hlreg0 |= IXGBE_HLREG0_RXCRCSTRP;
	else
		hlreg0 &= ~IXGBE_HLREG0_RXCRCSTRP;

	/* Configure jumbo frame support */
	if (dev->data->dev_conf.rxmode.jumbo_frame == 1) {
		hlreg0 |= IXGBE_HLREG0_JUMBOEN;
		maxfrs = IXGBE_READ_REG(hw, IXGBE_MAXFRS);
		maxfrs &= 0x0000FFFF;
		maxfrs |= (dev->data->dev_conf.rxmode.max_rx_pkt_len << 16);
		IXGBE_WRITE_REG(hw, IXGBE_MAXFRS, maxfrs);
	} else
		hlreg0 &= ~IXGBE_HLREG0_JUMBOEN;

	/* Configure loopback mode (82599 only) */
	if (hw->mac.type == ixgbe_mac_82599EB &&
	    dev->data->dev_conf.lpbk_mode == IXGBE_LPBK_82599_TX_RX)
		hlreg0 |= IXGBE_HLREG0_LPBK;

	IXGBE_WRITE_REG(hw, IXGBE_HLREG0, hlreg0);

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		struct rx_queue *rxq = eth_rx_queue_to_drv(dev->data->rx_queues[i]);
		physaddr_t bus_addr = rxq->ring_physaddr;
		uint32_t srrctl;

		/* Configure descriptor ring base and length */
		IXGBE_WRITE_REG(hw, IXGBE_RDBAL(rxq->reg_idx),
				(uint32_t)(bus_addr & 0x00000000ffffffffULL));
		IXGBE_WRITE_REG(hw, IXGBE_RDBAH(rxq->reg_idx),
				(uint32_t)(bus_addr >> 32));
		IXGBE_WRITE_REG(hw, IXGBE_RDLEN(rxq->reg_idx),
				rxq->len * sizeof(union ixgbe_adv_rx_desc));
		IXGBE_WRITE_REG(hw, IXGBE_RDH(rxq->reg_idx), 0);
		IXGBE_WRITE_REG(hw, IXGBE_RDT(rxq->reg_idx), 0);

		/* Configure the SRRCTL register */
#ifdef RTE_HEADER_SPLIT_ENABLE
		/* Configure Header Split */
		if (dev->data->dev_conf.rxmode.header_split) {
			if (hw->mac.type == ixgbe_mac_82599EB) {
				/* Must setup the PSRTYPE register */
				uint32_t psrtype;
				psrtype = IXGBE_PSRTYPE_TCPHDR |
					IXGBE_PSRTYPE_UDPHDR   |
					IXGBE_PSRTYPE_IPV4HDR  |
					IXGBE_PSRTYPE_IPV6HDR;
				IXGBE_WRITE_REG(hw, IXGBE_PSRTYPE(rxq->reg_idx), psrtype);
			}
			srrctl = ((dev->data->dev_conf.rxmode.split_hdr_size <<
				IXGBE_SRRCTL_BSIZEHDRSIZE_SHIFT) &
				IXGBE_SRRCTL_BSIZEHDR_MASK);
			srrctl |= E1000_SRRCTL_DESCTYPE_HDR_SPLIT_ALWAYS;
		} else
#endif
			srrctl = IXGBE_SRRCTL_DESCTYPE_ADV_ONEBUF;

		/* Drop packets when no room is left in the descriptor ring */
		srrctl |= IXGBE_SRRCTL_DROP_EN;

		/* Configure the buffer size (increments of KB) */
		srrctl |= ((IXGBE_MBUF_LEN >> IXGBE_SRRCTL_BSIZEPKT_SHIFT) &
			   IXGBE_SRRCTL_BSIZEPKT_MASK);
		IXGBE_WRITE_REG(hw, IXGBE_SRRCTL(rxq->reg_idx), srrctl);
	}

	/*
	 * Device configured with multiple RX queues.
	 */
	ixgbe_dev_mq_rx_configure(dev);

	/*
	 * Setup the Checksum Register.
	 * Disable Full-Packet Checksum which is mutually exclusive with RSS.
	 * Enable IP/L4 checkum computation by hardware if requested to do so.
	 */
	rxcsum = IXGBE_READ_REG(hw, IXGBE_RXCSUM);
	rxcsum |= IXGBE_RXCSUM_PCSD;
	if (dev->data->dev_conf.rxmode.hw_ip_checksum)
		rxcsum |= IXGBE_RXCSUM_IPPCSE;
	else
		rxcsum &= ~IXGBE_RXCSUM_IPPCSE;

	IXGBE_WRITE_REG(hw, IXGBE_RXCSUM, rxcsum);

	if (hw->mac.type == ixgbe_mac_82599EB) {
		rdrxctl = IXGBE_READ_REG(hw, IXGBE_RDRXCTL);
		if (dev->data->dev_conf.rxmode.hw_strip_crc)
			rdrxctl |= IXGBE_RDRXCTL_CRCSTRIP;
		else
			rdrxctl &= ~IXGBE_RDRXCTL_CRCSTRIP;
		rdrxctl &= ~IXGBE_RDRXCTL_RSCFRSTSIZE;
		IXGBE_WRITE_REG(hw, IXGBE_RDRXCTL, rdrxctl);
	}

	return 0;
}

/*
 * ixgbe_dcb_config_tx_hw_config - Configure general VMDq TX parameters
 * @hw: pointer to hardware structure
 */
static void 
ixgbe_vmdq_tx_hw_configure(struct ixgbe_hw *hw)
{
	uint32_t reg;
	uint32_t q;
	
	PMD_INIT_FUNC_TRACE();
	/*PF VF Transmit Enable*/
	IXGBE_WRITE_REG(hw, IXGBE_VFTE(0), UINT32_MAX);
	IXGBE_WRITE_REG(hw, IXGBE_VFTE(1), UINT32_MAX);

	/* Disable the Tx desc arbiter so that MTQC can be changed */
	reg = IXGBE_READ_REG(hw, IXGBE_RTTDCS);
	reg |= IXGBE_RTTDCS_ARBDIS;
	IXGBE_WRITE_REG(hw, IXGBE_RTTDCS, reg);

	reg = IXGBE_MTQC_VT_ENA | IXGBE_MTQC_64VF;
	IXGBE_WRITE_REG(hw, IXGBE_MTQC, reg);

	/* Disable drop for all queues */
	for (q = 0; q < IXGBE_MAX_RX_QUEUE_NUM; q++)
		IXGBE_WRITE_REG(hw, IXGBE_QDE,
	          (IXGBE_QDE_WRITE | (q << IXGBE_QDE_IDX_SHIFT)));

	/* Enable the Tx desc arbiter */
	reg = IXGBE_READ_REG(hw, IXGBE_RTTDCS);
	reg &= ~IXGBE_RTTDCS_ARBDIS;
	IXGBE_WRITE_REG(hw, IXGBE_RTTDCS, reg);

	IXGBE_WRITE_FLUSH(hw);

	return;
}

static int
ixgbe_dev_mq_tx_configure(struct rte_eth_dev *dev)
{
	struct ixgbe_hw *hw = 
		IXGBE_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	uint32_t mtqc;
	uint32_t rttdcs;

	if (hw->mac.type == ixgbe_mac_82598EB)
		return 0;

	/* disable arbiter before setting MTQC */
	rttdcs = IXGBE_READ_REG(hw, IXGBE_RTTDCS);
	rttdcs |= IXGBE_RTTDCS_ARBDIS;
	IXGBE_WRITE_REG(hw, IXGBE_RTTDCS, rttdcs);

	if (RTE_ETH_DEV_SRIOV(dev).active == 0) {
		/* 
	 	 * SRIOV inactive scheme
		 * any DCB w/o VMDq multi-queue setting
	 	 */
		if (dev->data->dev_conf.txmode.mq_mode == ETH_MQ_TX_VMDQ_ONLY)
			ixgbe_vmdq_tx_hw_configure(hw);
		else {
			mtqc = IXGBE_MTQC_64Q_1PB;
			IXGBE_WRITE_REG(hw, IXGBE_MTQC, mtqc);
		}
	} else {
		switch (RTE_ETH_DEV_SRIOV(dev).active) {

		/*
		 * SRIOV active scheme
		 * FIXME if support DCB together with VMDq & SRIOV
		 */
		case ETH_64_POOLS:
			mtqc = IXGBE_MTQC_VT_ENA | IXGBE_MTQC_64VF;
			break;
		case ETH_32_POOLS:
			mtqc = IXGBE_MTQC_VT_ENA | IXGBE_MTQC_32VF;
			break;
		case ETH_16_POOLS:
			mtqc = IXGBE_MTQC_VT_ENA | IXGBE_MTQC_RT_ENA | 
				IXGBE_MTQC_8TC_8TQ;
			break;
		default:
			mtqc = IXGBE_MTQC_64Q_1PB;
			log_err("ixgbe: invalid pool number in IOV mode\n");
		}
		IXGBE_WRITE_REG(hw, IXGBE_MTQC, mtqc);
	}

	/* re-enable arbiter */
	rttdcs &= ~IXGBE_RTTDCS_ARBDIS;
	IXGBE_WRITE_REG(hw, IXGBE_RTTDCS, rttdcs);

	return 0;
}

void ixgbe_dev_tx_init(struct rte_eth_dev *dev)
{
	int i;
	struct ixgbe_hw *hw;
	uint32_t hlreg0, txctrl;

        hw = IXGBE_DEV_PRIVATE_TO_HW(dev->data->dev_private);

	/* Enable TX CRC (checksum offload requirement) */
	hlreg0 = IXGBE_READ_REG(hw, IXGBE_HLREG0);
	hlreg0 |= IXGBE_HLREG0_TXCRCEN;
	IXGBE_WRITE_REG(hw, IXGBE_HLREG0, hlreg0);

	/* Setup the Base and Length of the Tx Descriptor Rings */
	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		struct tx_queue *txq = eth_tx_queue_to_drv(dev->data->tx_queues[i]);
		uint64_t bus_addr = txq->ring_physaddr;

		IXGBE_WRITE_REG(hw, IXGBE_TDBAL(txq->reg_idx),
				(uint32_t)(bus_addr & 0x00000000ffffffffULL));
		IXGBE_WRITE_REG(hw, IXGBE_TDBAH(txq->reg_idx),
				(uint32_t)(bus_addr >> 32));
		IXGBE_WRITE_REG(hw, IXGBE_TDLEN(txq->reg_idx),
				txq->len * sizeof(union ixgbe_adv_tx_desc));
		/* Setup the HW Tx Head and TX Tail descriptor pointers */
		IXGBE_WRITE_REG(hw, IXGBE_TDH(txq->reg_idx), 0);
		IXGBE_WRITE_REG(hw, IXGBE_TDT(txq->reg_idx), 0);

		/*
		 * Disable Tx Head Writeback RO bit, since this hoses
		 * bookkeeping if things aren't delivered in order.
		 */
		switch (hw->mac.type) {
		case ixgbe_mac_82598EB:
			txctrl = IXGBE_READ_REG(hw, IXGBE_DCA_TXCTRL(txq->reg_idx));
			txctrl &= ~IXGBE_DCA_TXCTRL_DESC_WRO_EN;
			IXGBE_WRITE_REG(hw, IXGBE_DCA_TXCTRL(txq->reg_idx), txctrl);
			break;

		case ixgbe_mac_82599EB:
		case ixgbe_mac_X540:
		default:
			txctrl = IXGBE_READ_REG(hw,
						IXGBE_DCA_TXCTRL_82599(txq->reg_idx));
			txctrl &= ~IXGBE_DCA_TXCTRL_DESC_WRO_EN;
			IXGBE_WRITE_REG(hw, IXGBE_DCA_TXCTRL_82599(txq->reg_idx),
					txctrl);
			break;
		}
	}

	/* Device configured with multiple TX queues. */
	ixgbe_dev_mq_tx_configure(dev);
}

/*
 * Set up link for 82599 loopback mode Tx->Rx.
 */
static void ixgbe_setup_loopback_link_82599(struct ixgbe_hw *hw)
{
	if (ixgbe_verify_lesm_fw_enabled_82599(hw)) {
		if (hw->mac.ops.acquire_swfw_sync(hw, IXGBE_GSSR_MAC_CSR_SM) !=
				IXGBE_SUCCESS) {
			log_err("ixgbe: Could not enable loopback mode\n");
			/* ignore error */
			return;
		}
	}

	/* Restart link */
	IXGBE_WRITE_REG(hw,
			IXGBE_AUTOC,
			IXGBE_AUTOC_LMS_10G_LINK_NO_AN | IXGBE_AUTOC_FLU);
	ixgbe_reset_pipeline_82599(hw);

	hw->mac.ops.release_swfw_sync(hw, IXGBE_GSSR_MAC_CSR_SM);
	delay_ms(50);
}

/**
 * ixgbe_dev_rxtx_start - enables queues and starts receiving packets
 * @dev: the ethernet device
 */
void ixgbe_dev_rxtx_start(struct rte_eth_dev *dev)
{
	int i, poll_ms;
	struct ixgbe_hw *hw;
	uint32_t dmatxctl;
	uint32_t rxctrl, txdctl, rxdctl;

	hw = IXGBE_DEV_PRIVATE_TO_HW(dev->data->dev_private);

	if (hw->mac.type != ixgbe_mac_82598EB) {
		dmatxctl = IXGBE_READ_REG(hw, IXGBE_DMATXCTL);
		dmatxctl |= IXGBE_DMATXCTL_TE;
		IXGBE_WRITE_REG(hw, IXGBE_DMATXCTL, dmatxctl);
	}

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		struct tx_queue *txq = eth_tx_queue_to_drv(dev->data->tx_queues[i]);
		txdctl = IXGBE_TXDCTL_ENABLE;
		txdctl |= (8 << 16); /* set WTHRESH = 8 */
		txdctl |= (1 << 8);  /* set HTHRESH = 1 */
		txdctl |= 32;        /* set PTHRESH = 32 */
		IXGBE_WRITE_REG(hw, IXGBE_TXDCTL(txq->reg_idx), txdctl);

		/* Wait until TX Enable ready */
		if (hw->mac.type == ixgbe_mac_82599EB) {
			poll_ms = 10;
			do {
				delay_ms(1);
				txdctl = IXGBE_READ_REG(hw, IXGBE_TXDCTL(txq->reg_idx));
			} while (--poll_ms && !(txdctl & IXGBE_TXDCTL_ENABLE));
			if (!poll_ms)
				log_err("ixgbe: Could not enable "
					"Tx Queue %d\n", i);
		}

		/* setup context descriptor 0 for IP/TCP checksums */
		ixgbe_tx_xmit_ctx(txq, OLFLAG_IP_CHKSUM | OLFLAG_TCP_CHKSUM, 0);
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		struct rx_queue *rxq = eth_rx_queue_to_drv(dev->data->rx_queues[i]);
		rxdctl = IXGBE_READ_REG(hw, IXGBE_RXDCTL(rxq->reg_idx));
		rxdctl |= IXGBE_RXDCTL_ENABLE;
		IXGBE_WRITE_REG(hw, IXGBE_RXDCTL(rxq->reg_idx), rxdctl);

		/* Wait until RX Enable ready */
		poll_ms = 10;
		do {
			delay_ms(1);
			rxdctl = IXGBE_READ_REG(hw, IXGBE_RXDCTL(rxq->reg_idx));
		} while (--poll_ms && !(rxdctl & IXGBE_RXDCTL_ENABLE));
		if (!poll_ms)
			log_err("ixgbe: Could not enable "
				"Rx Queue %d\n", i);
		wmb();
		IXGBE_WRITE_REG(hw, IXGBE_RDT(rxq->reg_idx),
				(rxq->tail & (rxq->len - 1)));
	}

	/* Enable Receive engine */
	rxctrl = IXGBE_READ_REG(hw, IXGBE_RXCTRL);
	if (hw->mac.type == ixgbe_mac_82598EB)
		rxctrl |= IXGBE_RXCTRL_DMBYPS;
	rxctrl |= IXGBE_RXCTRL_RXEN;
	hw->mac.ops.enable_rx_dma(hw, rxctrl);

	/* If loopback mode is enabled for 82599, set up the link accordingly */
	if (hw->mac.type == ixgbe_mac_82599EB &&
			dev->data->dev_conf.lpbk_mode == IXGBE_LPBK_82599_TX_RX)
		ixgbe_setup_loopback_link_82599(hw);
}

void ixgbe_dev_clear_queues(struct rte_eth_dev *dev)
{
	int i, j;
	struct tx_queue *txq;
	struct rx_queue *rxq;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = eth_tx_queue_to_drv(dev->data->tx_queues[i]);
		for (j = 0; j < txq->len; j++)
			mbuf_free(txq->ring_entries[j].mbuf);

		ixgbe_reset_tx_queue(txq);
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = eth_rx_queue_to_drv(dev->data->rx_queues[i]);
		ixgbe_clear_rx_queue(rxq);
	}
}

