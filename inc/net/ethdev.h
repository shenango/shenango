/*-
 *   BSD LICENSE
 * 
 *   Copyright(c) 2010-2013 Intel Corporation. All rights reserved.
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

#pragma once

#include <base/stddef.h>
#include <base/pci.h>
#include <net/mbuf.h>
#include <net/ethernet.h>

#include "ethqueue.h"

/* FIXME: figure out the right size for this */
#define RTE_ETHDEV_QUEUE_STAT_CNTRS	16

/**
 * A structure used to retrieve statistics for an Ethernet port.
 */
struct rte_eth_stats {
	uint64_t ipackets;  /**< Total number of successfully received packets. */
	uint64_t opackets;  /**< Total number of successfully transmitted packets.*/
	uint64_t ibytes;    /**< Total number of successfully received bytes. */
	uint64_t obytes;    /**< Total number of successfully transmitted bytes. */
	uint64_t ierrors;   /**< Total number of erroneous received packets. */
	uint64_t oerrors;   /**< Total number of failed transmitted packets. */
	uint64_t imcasts;   /**< Total number of multicast received packets. */
	uint64_t rx_nombuf; /**< Total number of RX mbuf allocation failures. */
	uint64_t fdirmatch; /**< Total number of RX packets matching a filter. */
	uint64_t fdirmiss;  /**< Total number of RX packets not matching any filter. */
	uint64_t tx_pause_xon;  /**< Total nb. of XON pause frame sent. */
	uint64_t rx_pause_xon;  /**< Total nb. of XON pause frame received. */
	uint64_t tx_pause_xoff; /**< Total nb. of XOFF pause frame sent. */
	uint64_t rx_pause_xoff; /**< Total nb. of XOFF pause frame received. */
	uint64_t q_ipackets[RTE_ETHDEV_QUEUE_STAT_CNTRS];
	/**< Total number of queue RX packets. */
	uint64_t q_opackets[RTE_ETHDEV_QUEUE_STAT_CNTRS];
	/**< Total number of queue TX packets. */
	uint64_t q_ibytes[RTE_ETHDEV_QUEUE_STAT_CNTRS];
	/**< Total number of successfully received queue bytes. */
	uint64_t q_obytes[RTE_ETHDEV_QUEUE_STAT_CNTRS];
	/**< Total number of successfully transmitted queue bytes. */
	uint64_t q_errors[RTE_ETHDEV_QUEUE_STAT_CNTRS];
	/**< Total number of queue packets received that are dropped. */
	uint64_t ilbpackets;
	/**< Total number of good packets received from loopback,VF Only */
	uint64_t olbpackets;
	/**< Total number of good packets transmitted to loopback,VF Only */
	uint64_t ilbbytes;
	/**< Total number of good bytes received from loopback,VF Only */
	uint64_t olbbytes;
	/**< Total number of good bytes transmitted to loopback,VF Only */
};

/**
 * A structure used to retrieve link-level information of an Ethernet port.
 */
struct rte_eth_link {
	uint16_t link_speed;      /**< ETH_LINK_SPEED_[10, 100, 1000, 10000] */
	uint16_t link_duplex;     /**< ETH_LINK_[HALF_DUPLEX, FULL_DUPLEX] */
	uint8_t  link_status : 1; /**< 1 -> link up, 0 -> link down */
}__attribute__((aligned(8)));     /**< aligned for atomic64 read/write */

#define ETH_LINK_SPEED_AUTONEG  0       /**< Auto-negotiate link speed. */
#define ETH_LINK_SPEED_10       10      /**< 10 megabits/second. */
#define ETH_LINK_SPEED_100      100     /**< 100 megabits/second. */
#define ETH_LINK_SPEED_1000     1000    /**< 1 gigabits/second. */
#define ETH_LINK_SPEED_10000    10000   /**< 10 gigabits/second. */

#define ETH_LINK_AUTONEG_DUPLEX 0       /**< Auto-negotiate duplex. */
#define ETH_LINK_HALF_DUPLEX    1       /**< Half-duplex connection. */
#define ETH_LINK_FULL_DUPLEX    2       /**< Full-duplex connection. */

/**
 * A structure used to configure the ring threshold registers of an RX/TX
 * queue for an Ethernet port.
 */
struct rte_eth_thresh {
	uint8_t pthresh; /**< Ring prefetch threshold. */
	uint8_t hthresh; /**< Ring host threshold. */
	uint8_t wthresh; /**< Ring writeback threshold. */
};

/**
 *  A set of values to identify what method is to be used to route
 *  packets to multiple queues.
 */
enum rte_eth_rx_mq_mode {
	ETH_MQ_RX_NONE = 0,  /**< None of DCB,RSS or VMDQ mode */

	ETH_MQ_RX_RSS,       /**< For RX side, only RSS is on */
	ETH_MQ_RX_DCB,       /**< For RX side,only DCB is on. */
	ETH_MQ_RX_DCB_RSS,   /**< Both DCB and RSS enable */

	ETH_MQ_RX_VMDQ_ONLY, /**< Only VMDQ, no RSS nor DCB */
	ETH_MQ_RX_VMDQ_RSS,  /**< RSS mode with VMDQ */
	ETH_MQ_RX_VMDQ_DCB,  /**< Use VMDQ+DCB to route traffic to queues */
	ETH_MQ_RX_VMDQ_DCB_RSS, /**< Enable both VMDQ and DCB in VMDq */
};

/**
 * for rx mq mode backward compatible 
 */
#define ETH_RSS                       ETH_MQ_RX_RSS
#define VMDQ_DCB                      ETH_MQ_RX_VMDQ_DCB
#define ETH_DCB_RX                    ETH_MQ_RX_DCB

/**
 * A set of values to identify what method is to be used to transmit 
 * packets using multi-TCs.
 */
enum rte_eth_tx_mq_mode {
	ETH_MQ_TX_NONE    = 0, 	/**< It is in neither DCB nor VT mode. */
	ETH_MQ_TX_DCB,         	/**< For TX side,only DCB is on. */
	ETH_MQ_TX_VMDQ_DCB,	/**< For TX side,both DCB and VT is on. */
	ETH_MQ_TX_VMDQ_ONLY,    /**< Only VT on, no DCB */
};

/**
 * for tx mq mode backward compatible 
 */
#define ETH_DCB_NONE                ETH_MQ_TX_NONE
#define ETH_VMDQ_DCB_TX             ETH_MQ_TX_VMDQ_DCB
#define ETH_DCB_TX                  ETH_MQ_TX_DCB

/**
 * A structure used to configure the RX features of an Ethernet port.
 */
struct rte_eth_rxmode {
	/** The multi-queue packet distribution mode to be used, e.g. RSS. */
	enum rte_eth_rx_mq_mode mq_mode;
	uint32_t max_rx_pkt_len;  /**< Only used if jumbo_frame enabled. */
	uint16_t split_hdr_size;  /**< hdr buf size (header_split enabled).*/
	uint8_t header_split : 1, /**< Header Split enable. */
		hw_ip_checksum   : 1, /**< IP/UDP/TCP checksum offload enable. */
		hw_vlan_filter   : 1, /**< VLAN filter enable. */
		hw_vlan_strip    : 1, /**< VLAN strip enable. */
		hw_vlan_extend   : 1, /**< Extended VLAN enable. */
		jumbo_frame      : 1, /**< Jumbo Frame Receipt enable. */
		hw_strip_crc     : 1; /**< Enable CRC stripping by hardware. */
};

/**
 * A structure used to configure the Receive Side Scaling (RSS) feature
 * of an Ethernet port.
 * If not NULL, the *rss_key* pointer of the *rss_conf* structure points
 * to an array of 40 bytes holding the RSS key to use for hashing specific
 * header fields of received packets.
 * Otherwise, a default random hash key is used by the device driver.
 *
 * The *rss_hf* field of the *rss_conf* structure indicates the different
 * types of IPv4/IPv6 packets to which the RSS hashing must be applied.
 * Supplying an *rss_hf* equal to zero disables the RSS feature.
 */
struct rte_eth_rss_conf {
	uint8_t  *rss_key;   /**< If not NULL, 40-byte hash key. */
	uint16_t rss_hf;     /**< Hash functions to apply - see below. */
};

#define ETH_RSS_IPV4        0x0001 /**< IPv4 packet. */
#define ETH_RSS_IPV4_TCP    0x0002 /**< IPv4/TCP packet. */
#define ETH_RSS_IPV6        0x0004 /**< IPv6 packet. */
#define ETH_RSS_IPV6_EX     0x0008 /**< IPv6 packet with extension headers.*/
#define ETH_RSS_IPV6_TCP    0x0010 /**< IPv6/TCP packet. */
#define ETH_RSS_IPV6_TCP_EX 0x0020 /**< IPv6/TCP with extension headers. */
/* Intel RSS extensions to UDP packets */
#define ETH_RSS_IPV4_UDP    0x0040 /**< IPv4/UDP packet. */
#define ETH_RSS_IPV6_UDP    0x0080 /**< IPv6/UDP packet. */
#define ETH_RSS_IPV6_UDP_EX 0x0100 /**< IPv6/UDP with extension headers. */
/* Definitions used for redirection table entry size */
#define ETH_RSS_RETA_NUM_ENTRIES 128
#define ETH_RSS_RETA_MAX_QUEUE   16  

/* Definitions used for VMDQ and DCB functionality */
#define ETH_VMDQ_MAX_VLAN_FILTERS   64 /**< Maximum nb. of VMDQ vlan filters. */
#define ETH_DCB_NUM_USER_PRIORITIES 8  /**< Maximum nb. of DCB priorities. */
#define ETH_VMDQ_DCB_NUM_QUEUES     128 /**< Maximum nb. of VMDQ DCB queues. */
#define ETH_DCB_NUM_QUEUES          128 /**< Maximum nb. of DCB queues. */

/* DCB capability defines */
#define ETH_DCB_PG_SUPPORT      0x00000001 /**< Priority Group(ETS) support. */
#define ETH_DCB_PFC_SUPPORT     0x00000002 /**< Priority Flow Control support. */ 

/* Definitions used for VLAN Offload functionality */
#define ETH_VLAN_STRIP_OFFLOAD   0x0001 /**< VLAN Strip  On/Off */
#define ETH_VLAN_FILTER_OFFLOAD  0x0002 /**< VLAN Filter On/Off */
#define ETH_VLAN_EXTEND_OFFLOAD  0x0004 /**< VLAN Extend On/Off */

/* Definitions used for mask VLAN setting */
#define ETH_VLAN_STRIP_MASK   0x0001 /**< VLAN Strip  setting mask */
#define ETH_VLAN_FILTER_MASK  0x0002 /**< VLAN Filter  setting mask*/
#define ETH_VLAN_EXTEND_MASK  0x0004 /**< VLAN Extend  setting mask*/
#define ETH_VLAN_ID_MAX       0x0FFF /**< VLAN ID is in lower 12 bits*/ 

/* Definitions used for receive MAC address   */
#define ETH_NUM_RECEIVE_MAC_ADDR  128 /**< Maximum nb. of receive mac addr. */


/* Definitions used for unicast hash  */
#define ETH_VMDQ_NUM_UC_HASH_ARRAY  128 /**< Maximum nb. of UC hash array. */

/* Definitions used for VMDQ pool rx mode setting */
#define ETH_VMDQ_ACCEPT_UNTAG   0x0001 /**< accept untagged packets. */
#define ETH_VMDQ_ACCEPT_HASH_MC 0x0002 /**< accept packets in multicast table . */
#define ETH_VMDQ_ACCEPT_HASH_UC 0x0004 /**< accept packets in unicast table. */
#define ETH_VMDQ_ACCEPT_BROADCAST   0x0008 /**< accept broadcast packets. */
#define ETH_VMDQ_ACCEPT_MULTICAST   0x0010 /**< multicast promiscuous. */

/* Definitions used for VMDQ mirror rules setting */
#define ETH_VMDQ_NUM_MIRROR_RULE     4 /**< Maximum nb. of mirror rules. . */

#define ETH_VMDQ_POOL_MIRROR    0x0001 /**< Virtual Pool Mirroring. */
#define ETH_VMDQ_UPLINK_MIRROR  0x0002 /**< Uplink Port Mirroring. */
#define ETH_VMDQ_DOWNLIN_MIRROR 0x0004 /**< Downlink Port Mirroring. */
#define ETH_VMDQ_VLAN_MIRROR    0x0008 /**< VLAN Mirroring. */

/**
 * A structure used to configure VLAN traffic mirror of an Ethernet port.
 */
struct rte_eth_vlan_mirror {
	uint64_t vlan_mask; /**< mask for valid VLAN ID. */
	uint16_t vlan_id[ETH_VMDQ_MAX_VLAN_FILTERS]; 
	/** VLAN ID list for vlan mirror. */
};

/**
 * A structure used to configure traffic mirror of an Ethernet port.
 */
struct rte_eth_vmdq_mirror_conf {
	uint8_t rule_type_mask; /**< Mirroring rule type mask we want to set */
	uint8_t dst_pool; /**< Destination pool for this mirror rule. */
	uint64_t pool_mask; /**< Bitmap of pool for pool mirroring */
	struct rte_eth_vlan_mirror vlan; /**< VLAN ID setting for VLAN mirroring */
};

/**
 * A structure used to configure Redirection Table of  the Receive Side
 * Scaling (RSS) feature of an Ethernet port.
 */
struct rte_eth_rss_reta {
	/** First 64 mask bits indicate which entry(s) need to updated/queried. */
	uint64_t mask_lo; 
	/** Second 64 mask bits indicate which entry(s) need to updated/queried. */
	uint64_t mask_hi; 
	uint8_t reta[ETH_RSS_RETA_NUM_ENTRIES];  /**< 128 RETA entries*/
};

/**
 * This enum indicates the possible number of traffic classes
 * in DCB configratioins
 */
enum rte_eth_nb_tcs {
	ETH_4_TCS = 4, /**< 4 TCs with DCB. */
	ETH_8_TCS = 8  /**< 8 TCs with DCB. */
};

/**
 * This enum indicates the possible number of queue pools
 * in VMDQ configurations.
 */
enum rte_eth_nb_pools {
	ETH_8_POOLS = 8,    /**< 8 VMDq pools. */
	ETH_16_POOLS = 16,  /**< 16 VMDq pools. */
	ETH_32_POOLS = 32,  /**< 32 VMDq pools. */
	ETH_64_POOLS = 64   /**< 64 VMDq pools. */
};

/* This structure may be extended in future. */
struct rte_eth_dcb_rx_conf {
	enum rte_eth_nb_tcs nb_tcs; /**< Possible DCB TCs, 4 or 8 TCs */
	uint8_t dcb_queue[ETH_DCB_NUM_USER_PRIORITIES];
	/**< Possible DCB queue,4 or 8. */
};
 
struct rte_eth_vmdq_dcb_tx_conf {
	enum rte_eth_nb_pools nb_queue_pools; /**< With DCB, 16 or 32 pools. */
	uint8_t dcb_queue[ETH_DCB_NUM_USER_PRIORITIES];
	/**< Possible DCB queue,4 or 8. */
};
 
struct rte_eth_dcb_tx_conf {
	enum rte_eth_nb_tcs nb_tcs; /**< Possible DCB TCs, 4 or 8 TCs. */
	uint8_t dcb_queue[ETH_DCB_NUM_USER_PRIORITIES];
	/**< Possible DCB queue,4 or 8. */
};

struct rte_eth_vmdq_tx_conf {
	enum rte_eth_nb_pools nb_queue_pools; /**< VMDq mode, 64 pools. */
};

/**
 * A structure used to configure the VMDQ+DCB feature
 * of an Ethernet port.
 *
 * Using this feature, packets are routed to a pool of queues, based
 * on the vlan id in the vlan tag, and then to a specific queue within
 * that pool, using the user priority vlan tag field.
 *
 * A default pool may be used, if desired, to route all traffic which
 * does not match the vlan filter rules.
 */
struct rte_eth_vmdq_dcb_conf {
	enum rte_eth_nb_pools nb_queue_pools; /**< With DCB, 16 or 32 pools */
	uint8_t enable_default_pool; /**< If non-zero, use a default pool */
	uint8_t default_pool; /**< The default pool, if applicable */
	uint8_t nb_pool_maps; /**< We can have up to 64 filters/mappings */
	struct {
		uint16_t vlan_id; /**< The vlan id of the received frame */
		uint64_t pools;   /**< Bitmask of pools for packet rx */
	} pool_map[ETH_VMDQ_MAX_VLAN_FILTERS]; /**< VMDq vlan pool maps. */
	uint8_t dcb_queue[ETH_DCB_NUM_USER_PRIORITIES];
	/**< Selects a queue in a pool */
};

struct rte_eth_vmdq_rx_conf {
	enum rte_eth_nb_pools nb_queue_pools; /**< VMDq only mode, 8 or 64 pools */
	uint8_t enable_default_pool; /**< If non-zero, use a default pool */
	uint8_t default_pool; /**< The default pool, if applicable */
	uint8_t nb_pool_maps; /**< We can have up to 64 filters/mappings */
	struct {
		uint16_t vlan_id; /**< The vlan id of the received frame */
		uint64_t pools;   /**< Bitmask of pools for packet rx */
	} pool_map[ETH_VMDQ_MAX_VLAN_FILTERS]; /**< VMDq vlan pool maps. */
};

/**
 * A structure used to configure the TX features of an Ethernet port.
 */
struct rte_eth_txmode {
	enum rte_eth_tx_mq_mode mq_mode; /**< TX multi-queues mode. */
};

/**
 * A structure used to configure an RX ring of an Ethernet port.
 */
struct rte_eth_rxconf {
	struct rte_eth_thresh rx_thresh; /**< RX ring threshold registers. */
	uint16_t rx_free_thresh; /**< Drives the freeing of RX descriptors. */
	uint8_t rx_drop_en; /**< Drop packets if no descriptors are available. */
};

#define ETH_TXQ_FLAGS_NOMULTSEGS 0x0001 /**< nb_segs=1 for all mbufs */
#define ETH_TXQ_FLAGS_NOREFCOUNT 0x0002 /**< refcnt can be ignored */
#define ETH_TXQ_FLAGS_NOMULTMEMP 0x0004 /**< all bufs come from same mempool */
#define ETH_TXQ_FLAGS_NOVLANOFFL 0x0100 /**< disable VLAN offload */
#define ETH_TXQ_FLAGS_NOXSUMSCTP 0x0200 /**< disable SCTP checksum offload */
#define ETH_TXQ_FLAGS_NOXSUMUDP  0x0400 /**< disable UDP checksum offload */
#define ETH_TXQ_FLAGS_NOXSUMTCP  0x0800 /**< disable TCP checksum offload */
#define ETH_TXQ_FLAGS_NOOFFLOADS \
		(ETH_TXQ_FLAGS_NOVLANOFFL | ETH_TXQ_FLAGS_NOXSUMSCTP | \
		 ETH_TXQ_FLAGS_NOXSUMUDP  | ETH_TXQ_FLAGS_NOXSUMTCP)
/**
 * A structure used to configure a TX ring of an Ethernet port.
 */
struct rte_eth_txconf {
	struct rte_eth_thresh tx_thresh; /**< TX ring threshold registers. */
	uint16_t tx_rs_thresh; /**< Drives the setting of RS bit on TXDs. */
	uint16_t tx_free_thresh; /**< Drives the freeing of TX buffers. */
	uint32_t txq_flags; /**< Set flags for the Tx queue */
};

/**
 * This enum indicates the flow control mode
 */
enum rte_eth_fc_mode {
	RTE_FC_NONE = 0, /**< Disable flow control. */
	RTE_FC_RX_PAUSE, /**< RX pause frame, enable flowctrl on TX side. */
	RTE_FC_TX_PAUSE, /**< TX pause frame, enable flowctrl on RX side. */
	RTE_FC_FULL      /**< Enable flow control on both side. */
};

/**
 * A structure used to configure Ethernet flow control parameter.
 * These parameters will be configured into the register of the NIC.
 * Please refer to the corresponding data sheet for proper value.
 */
struct rte_eth_fc_conf {
	uint32_t high_water;  /**< High threshold value to trigger XOFF */
	uint32_t low_water;   /**< Low threshold value to trigger XON */
	uint16_t pause_time;  /**< Pause quota in the Pause frame */
	uint16_t send_xon;    /**< Is XON frame need be sent */
	enum rte_eth_fc_mode mode;  /**< Link flow control mode */
};

/**
 * A structure used to configure Ethernet priority flow control parameter.
 * These parameters will be configured into the register of the NIC.
 * Please refer to the corresponding data sheet for proper value.
 */
struct rte_eth_pfc_conf {
	struct rte_eth_fc_conf fc; /**< General flow control parameter. */
	uint8_t priority;          /**< VLAN User Priority. */
};

/**
 *  Flow Director setting modes: none (default), signature or perfect.
 */
enum rte_fdir_mode {
	RTE_FDIR_MODE_NONE      = 0, /**< Disable FDIR support. */
	RTE_FDIR_MODE_SIGNATURE,     /**< Enable FDIR signature filter mode. */
	RTE_FDIR_MODE_PERFECT,       /**< Enable FDIR perfect filter mode. */
};

/**
 *  Memory space that can be configured to store Flow Director filters
 *  in the board memory.
 */
enum rte_fdir_pballoc_type {
	RTE_FDIR_PBALLOC_64K = 0,  /**< 64k. */
	RTE_FDIR_PBALLOC_128K,     /**< 128k. */
	RTE_FDIR_PBALLOC_256K,     /**< 256k. */
};

/**
 *  Select report mode of FDIR hash information in RX descriptors.
 */
enum rte_fdir_status_mode {
	RTE_FDIR_NO_REPORT_STATUS = 0, /**< Never report FDIR hash. */
	RTE_FDIR_REPORT_STATUS, /**< Only report FDIR hash for matching pkts. */
	RTE_FDIR_REPORT_STATUS_ALWAYS, /**< Always report FDIR hash. */
};

/**
 * A structure used to configure the Flow Director (FDIR) feature
 * of an Ethernet port.
 *
 * If mode is RTE_FDIR_DISABLE, the pballoc value is ignored.
 */
struct rte_fdir_conf {
	enum rte_fdir_mode mode; /**< Flow Director mode. */
	enum rte_fdir_pballoc_type pballoc; /**< Space for FDIR filters. */
	enum rte_fdir_status_mode status;  /**< How to report FDIR hash. */
	/** Offset of flexbytes field in RX packets (in 16-bit word units). */
	uint8_t flexbytes_offset;
	/** RX queue of packets matching a "drop" filter in perfect mode. */
	uint8_t drop_queue;
};

/**
 *  Possible l4type of FDIR filters.
 */
enum rte_l4type {
	RTE_FDIR_L4TYPE_NONE = 0,       /**< None. */
	RTE_FDIR_L4TYPE_UDP,            /**< UDP. */
	RTE_FDIR_L4TYPE_TCP,            /**< TCP. */
	RTE_FDIR_L4TYPE_SCTP,           /**< SCTP. */
};

/**
 *  Select IPv4 or IPv6 FDIR filters.
 */
enum rte_iptype {
	RTE_FDIR_IPTYPE_IPV4 = 0,     /**< IPv4. */
	RTE_FDIR_IPTYPE_IPV6 ,        /**< IPv6. */
};

/**
 *  A structure used to define a FDIR packet filter.
 */
struct rte_fdir_filter {
	uint16_t flex_bytes; /**< Flex bytes value to match. */
	uint16_t vlan_id; /**< VLAN ID value to match, 0 otherwise. */
	uint16_t port_src; /**< Source port to match, 0 otherwise. */
	uint16_t port_dst; /**< Destination port to match, 0 otherwise. */
	union {
		uint32_t ipv4_addr; /**< IPv4 source address to match. */
		uint32_t ipv6_addr[4]; /**< IPv6 source address to match. */
	} ip_src; /**< IPv4/IPv6 source address to match (union of above). */
	union {
		uint32_t ipv4_addr; /**< IPv4 destination address to match. */
		uint32_t ipv6_addr[4]; /**< IPv6 destination address to match */
	} ip_dst; /**< IPv4/IPv6 destination address to match (union of above). */
	enum rte_l4type l4type; /**< l4type to match: NONE/UDP/TCP/SCTP. */
	enum rte_iptype iptype; /**< IP packet type to match: IPv4 or IPv6. */
};

/**
 *  A structure used to configure FDIR masks that are used by the device
 *  to match the various fields of RX packet headers.
 *  @note The only_ip_flow field has the opposite meaning compared to other
 *  masks!
 */
struct rte_fdir_masks {
	/** When set to 1, packet l4type is \b NOT relevant in filters, and
	   source and destination port masks must be set to zero. */
	uint8_t only_ip_flow;
	/** If set to 1, vlan_id is relevant in filters. */
	uint8_t vlan_id;
	/** If set to 1, vlan_prio is relevant in filters. */
	uint8_t vlan_prio;
	/** If set to 1, flexbytes is relevant in filters. */
	uint8_t flexbytes;
	/** If set to 1, set the IPv6 masks. Otherwise set the IPv4 masks. */
	uint8_t set_ipv6_mask;
	/** When set to 1, comparison of destination IPv6 address with IP6AT
	    registers is meaningful. */
	uint8_t comp_ipv6_dst;
	/** Mask of Destination IPv4 Address. All bits set to 1 define the
	    relevant bits to use in the destination address of an IPv4 packet
	    when matching it against FDIR filters. */
	uint32_t dst_ipv4_mask;
	/** Mask of Source IPv4 Address. All bits set to 1 define
	    the relevant bits to use in the source address of an IPv4 packet
	    when matching it against FDIR filters. */
	uint32_t src_ipv4_mask;
	/** Mask of Source IPv6 Address. All bits set to 1 define the
	    relevant BYTES to use in the source address of an IPv6 packet
	    when matching it against FDIR filters. */
	uint16_t dst_ipv6_mask;
	/** Mask of Destination IPv6 Address. All bits set to 1 define the
	    relevant BYTES to use in the destination address of an IPv6 packet
	    when matching it against FDIR filters. */
	uint16_t src_ipv6_mask;
	/** Mask of Source Port. All bits set to 1 define the relevant
	    bits to use in the source port of an IP packets when matching it
	    against FDIR filters. */
	uint16_t src_port_mask;
	/** Mask of Destination Port. All bits set to 1 define the relevant
	    bits to use in the destination port of an IP packet when matching it
	    against FDIR filters. */
	uint16_t dst_port_mask;
};

/**
 *  A structure used to report the status of the flow director filters in use.
 */
struct rte_eth_fdir {
	/** Number of filters with collision indication. */
	uint16_t collision;
	/** Number of free (non programmed) filters. */
	uint16_t free;
	/** The Lookup hash value of the added filter that updated the value
	   of the MAXLEN field */
	uint16_t maxhash;
	/** Longest linked list of filters in the table. */
	uint8_t maxlen;
	/** Number of added filters. */
	uint64_t add;
	/** Number of removed filters. */
	uint64_t remove;
	/** Number of failed added filters (no more space in device). */
	uint64_t f_add;
	/** Number of failed removed filters. */
	uint64_t f_remove;
};

/**
 * A structure used to enable/disable specific device interrupts.
 */
struct rte_intr_conf {
	/** enable/disable lsc interrupt. 0 (default) - disable, 1 enable */
	uint16_t lsc;
};

/**
 * A structure used to configure an Ethernet port.
 * Depending upon the RX multi-queue mode, extra advanced
 * configuration settings may be needed.
 */
struct rte_eth_conf {
	uint16_t link_speed;
	/**< ETH_LINK_SPEED_10[0|00|000], or 0 for autonegotation */
	uint16_t link_duplex;
	/**< ETH_LINK_[HALF_DUPLEX|FULL_DUPLEX], or 0 for autonegotation */
	struct rte_eth_rxmode rxmode; /**< Port RX configuration. */
	struct rte_eth_txmode txmode; /**< Port TX configuration. */
	uint32_t lpbk_mode; /**< Loopback operation mode. By default the value
			         is 0, meaning the loopback mode is disabled.
				 Read the datasheet of given ethernet controller
				 for details. The possible values of this field
				 are defined in implementation of each driver. */
	union {
		struct rte_eth_rss_conf rss_conf; /**< Port RSS configuration */
		struct rte_eth_vmdq_dcb_conf vmdq_dcb_conf;
		/**< Port vmdq+dcb configuration. */
		struct rte_eth_dcb_rx_conf dcb_rx_conf;
		/**< Port dcb RX configuration. */
		struct rte_eth_vmdq_rx_conf vmdq_rx_conf;
		/**< Port vmdq RX configuration. */
	} rx_adv_conf; /**< Port RX filtering configuration (union). */
	union {
		struct rte_eth_vmdq_dcb_tx_conf vmdq_dcb_tx_conf;
		/**< Port vmdq+dcb TX configuration. */
		struct rte_eth_dcb_tx_conf dcb_tx_conf;
		/**< Port dcb TX configuration. */
		struct rte_eth_vmdq_tx_conf vmdq_tx_conf;
		/**< Port vmdq TX configuration. */
	} tx_adv_conf; /**< Port TX DCB configuration (union). */
	/** Currently,Priority Flow Control(PFC) are supported,if DCB with PFC 
 	    is needed,and the variable must be set ETH_DCB_PFC_SUPPORT. */ 
	uint32_t dcb_capability_en; 
	struct rte_fdir_conf fdir_conf; /**< FDIR configuration. */
	struct rte_intr_conf intr_conf; /**< Interrupt mode configuration. */
};

/**
 * A structure used to retrieve the contextual information of
 * an Ethernet device, such as the controlling driver of the device,
 * its PCI context, etc...
 */

/**
 * RX offload capabilities of a device.
 */
#define DEV_RX_OFFLOAD_VLAN_STRIP  0x00000001
#define DEV_RX_OFFLOAD_IPV4_CKSUM  0x00000002
#define DEV_RX_OFFLOAD_UDP_CKSUM   0x00000004
#define DEV_RX_OFFLOAD_TCP_CKSUM   0x00000008
#define DEV_RX_OFFLOAD_TCP_LRO     0x00000010

/**
 * TX offload capabilities of a device.
 */
#define DEV_TX_OFFLOAD_VLAN_INSERT 0x00000001
#define DEV_TX_OFFLOAD_IPV4_CKSUM  0x00000002
#define DEV_TX_OFFLOAD_UDP_CKSUM   0x00000004
#define DEV_TX_OFFLOAD_TCP_CKSUM   0x00000008
#define DEV_TX_OFFLOAD_SCTP_CKSUM  0x00000010
#define DEV_TX_OFFLOAD_TCP_TSO     0x00000020
#define DEV_TX_OFFLOAD_UDP_TSO     0x00000040

struct rte_eth_dev_info {
	struct pci_dev *pci_dev; /**< Device PCI information. */
	const char *driver_name; /**< Device Driver name. */
	uint32_t min_rx_bufsize; /**< Minimum size of RX buffer. */
	uint32_t max_rx_pktlen; /**< Maximum configurable length of RX pkt. */
	uint16_t max_rx_queues; /**< Maximum number of RX queues. */
	uint16_t max_tx_queues; /**< Maximum number of TX queues. */
	uint16_t nb_rx_fgs;	/**< The number of flow groups. */
	uint32_t max_mac_addrs; /**< Maximum number of MAC addresses. */
	uint32_t max_hash_mac_addrs; 
	/** Maximum number of hash MAC addresses for MTA and UTA. */
	uint16_t max_vfs; /**< Maximum number of VFs. */
	uint16_t max_vmdq_pools; /**< Maximum number of VMDq pools. */
	uint32_t rx_offload_capa; /**< Device RX offload capabilities. */
	uint32_t tx_offload_capa; /**< Device TX offload capabilities. */
};

struct rte_eth_dev;

/*
 * Definitions of all functions exported by an Ethernet driver through the
 * the generic structure of type *eth_dev_ops* supplied in the *rte_eth_dev*
 * structure associated with an Ethernet device.
 */

typedef int  (*eth_dev_configure_t)(struct rte_eth_dev *dev);
/**< @internal Ethernet device configuration. */

typedef int  (*eth_dev_start_t)(struct rte_eth_dev *dev);
/**< @internal Function used to start a configured Ethernet device. */

typedef void (*eth_dev_stop_t)(struct rte_eth_dev *dev);
/**< @internal Function used to stop a configured Ethernet device. */

typedef void (*eth_dev_close_t)(struct rte_eth_dev *dev);
/**< @internal Function used to close a configured Ethernet device. */

typedef void (*eth_promiscuous_enable_t)(struct rte_eth_dev *dev);
/**< @internal Function used to enable the RX promiscuous mode of an Ethernet device. */

typedef void (*eth_promiscuous_disable_t)(struct rte_eth_dev *dev);
/**< @internal Function used to disable the RX promiscuous mode of an Ethernet device. */

typedef void (*eth_allmulticast_enable_t)(struct rte_eth_dev *dev);
/**< @internal Enable the receipt of all multicast packets by an Ethernet device. */

typedef void (*eth_allmulticast_disable_t)(struct rte_eth_dev *dev);
/**< @internal Disable the receipt of all multicast packets by an Ethernet device. */

typedef int (*eth_link_update_t)(struct rte_eth_dev *dev,
				int wait_to_complete);
/**< @internal Get link speed, duplex mode and state (up/down) of an Ethernet device. */

typedef void (*eth_stats_get_t)(struct rte_eth_dev *dev,
				struct rte_eth_stats *igb_stats);
/**< @internal Get global I/O statistics of an Ethernet device. */

typedef void (*eth_stats_reset_t)(struct rte_eth_dev *dev);
/**< @internal Reset global I/O statistics of an Ethernet device to 0. */

typedef int (*eth_queue_stats_mapping_set_t)(struct rte_eth_dev *dev,
					     uint16_t queue_id,
					     uint8_t stat_idx,
					     uint8_t is_rx);
/**< @internal Set a queue statistics mapping for a tx/rx queue of an Ethernet device. */

typedef void (*eth_dev_infos_get_t)(struct rte_eth_dev *dev,
				    struct rte_eth_dev_info *dev_info);
/**< @internal Get specific informations of an Ethernet device. */

typedef int (*eth_rx_queue_setup_t)(struct rte_eth_dev *dev,
				    int rx_queue_id,
				    int numa_node,
				    uint16_t nb_rx_desc,
				    struct mbuf_allocator *a);
/**< @internal Initialize a receive queue of an Ethernet device. */

typedef int (*eth_tx_queue_setup_t)(struct rte_eth_dev *dev,
				    int tx_queue_id,
				    int numa_node,
				    uint16_t nb_tx_desc);
/**< @internal Initialize a transmit queue of an Ethernet device. */
struct eth_rx_queue;
struct eth_tx_queue;
typedef void (*eth_rx_queue_release_t)(struct eth_rx_queue *queue);
typedef void (*eth_tx_queue_release_t)(struct eth_tx_queue *queue);
/**< @internal Release memory resources allocated by given RX/TX queue. */

typedef int (*vlan_filter_set_t)(struct rte_eth_dev *dev,
				  uint16_t vlan_id,
				  int on);
/**< @internal filtering of a VLAN Tag Identifier by an Ethernet device. */

typedef void (*vlan_tpid_set_t)(struct rte_eth_dev *dev,
				  uint16_t tpid);
/**< @internal set the outer VLAN-TPID by an Ethernet device. */

typedef void (*vlan_offload_set_t)(struct rte_eth_dev *dev, int mask);
/**< @internal set VLAN offload function by an Ethernet device. */

typedef void (*vlan_strip_queue_set_t)(struct rte_eth_dev *dev,
				  uint16_t rx_queue_id,
				  int on);
/**< @internal Send output packets on a transmit queue of an Ethernet device. */

typedef int (*fdir_add_signature_filter_t)(struct rte_eth_dev *dev,
					   struct rte_fdir_filter *fdir_ftr,
					   uint8_t rx_queue);
/**< @internal Setup a new signature filter rule on an Ethernet device */

typedef int (*fdir_update_signature_filter_t)(struct rte_eth_dev *dev,
					      struct rte_fdir_filter *fdir_ftr,
					      uint8_t rx_queue);
/**< @internal Update a signature filter rule on an Ethernet device */

typedef int (*fdir_remove_signature_filter_t)(struct rte_eth_dev *dev,
					      struct rte_fdir_filter *fdir_ftr);
/**< @internal Remove a  signature filter rule on an Ethernet device */

typedef void (*fdir_infos_get_t)(struct rte_eth_dev *dev,
				 struct rte_eth_fdir *fdir);
/**< @internal Get information about fdir status */

typedef int (*fdir_add_perfect_filter_t)(struct rte_eth_dev *dev,
					 struct rte_fdir_filter *fdir_ftr,
					 uint16_t soft_id, uint8_t rx_queue,
					 uint8_t drop);
/**< @internal Setup a new perfect filter rule on an Ethernet device */

typedef int (*fdir_update_perfect_filter_t)(struct rte_eth_dev *dev,
					    struct rte_fdir_filter *fdir_ftr,
					    uint16_t soft_id, uint8_t rx_queue,
					    uint8_t drop);
/**< @internal Update a perfect filter rule on an Ethernet device */

typedef int (*fdir_remove_perfect_filter_t)(struct rte_eth_dev *dev,
					    struct rte_fdir_filter *fdir_ftr,
					    uint16_t soft_id);
/**< @internal Remove a perfect filter rule on an Ethernet device */

typedef int (*fdir_set_masks_t)(struct rte_eth_dev *dev,
				struct rte_fdir_masks *fdir_masks);
/**< @internal Setup flow director masks on an Ethernet device */

typedef int (*flow_ctrl_set_t)(struct rte_eth_dev *dev,
				struct rte_eth_fc_conf *fc_conf);
/**< @internal Setup flow control parameter on an Ethernet device */

typedef int (*priority_flow_ctrl_set_t)(struct rte_eth_dev *dev,
				struct rte_eth_pfc_conf *pfc_conf);
/**< @internal Setup priority flow control parameter on an Ethernet device */

typedef int (*reta_update_t)(struct rte_eth_dev *dev,
				struct rte_eth_rss_reta *reta_conf);
/**< @internal Update RSS redirection table on an Ethernet device */

typedef int (*reta_query_t)(struct rte_eth_dev *dev,
				struct rte_eth_rss_reta *reta_conf);
/**< @internal Query RSS redirection table on an Ethernet device */

typedef int (*eth_dev_led_on_t)(struct rte_eth_dev *dev);
/**< @internal Turn on SW controllable LED on an Ethernet device */

typedef int (*eth_dev_led_off_t)(struct rte_eth_dev *dev);
/**< @internal Turn off SW controllable LED on an Ethernet device */

typedef void (*eth_mac_addr_remove_t)(struct rte_eth_dev *dev, uint32_t index);
/**< @internal Remove MAC address from receive address register */

typedef void (*eth_mac_addr_add_t)(struct rte_eth_dev *dev,
				  struct eth_addr *mac_addr,
				  uint32_t index,
				  uint32_t vmdq);
/**< @internal Set a MAC address into Receive Address Address Register */ 

typedef int (*eth_uc_hash_table_set_t)(struct rte_eth_dev *dev,
				  struct eth_addr *mac_addr,
				  uint8_t on);
/**< @internal Set a Unicast Hash bitmap */

typedef int (*eth_uc_all_hash_table_set_t)(struct rte_eth_dev *dev,
				  uint8_t on);
/**< @internal Set all Unicast Hash bitmap */

typedef int (*eth_set_vf_rx_mode_t)(struct rte_eth_dev *dev,
				  uint16_t vf,
				  uint16_t rx_mode, 
				  uint8_t on);
/**< @internal Set a VF receive mode */

typedef int (*eth_set_vf_rx_t)(struct rte_eth_dev *dev,
				uint16_t vf,
				uint8_t on);
/**< @internal Set a VF receive  mode */

typedef int (*eth_set_vf_tx_t)(struct rte_eth_dev *dev,
				uint16_t vf,
				uint8_t on);
/**< @internal Enable or disable a VF transmit   */

typedef int (*eth_set_vf_vlan_filter_t)(struct rte_eth_dev *dev, 
				  uint16_t vlan, 
				  uint64_t vf_mask,
				  uint8_t vlan_on);
/**< @internal Set VF VLAN pool filter */

typedef int (*eth_mirror_rule_set_t)(struct rte_eth_dev *dev,
				  struct rte_eth_vmdq_mirror_conf *mirror_conf,
				  uint8_t rule_id, 
				  uint8_t on);
/**< @internal Add a traffic mirroring rule on an Ethernet device */

typedef int (*eth_mirror_rule_reset_t)(struct rte_eth_dev *dev,
				  uint8_t rule_id);
/**< @internal Remove a traffic mirroring rule on an Ethernet device */

/**
 * @internal A structure containing the functions exported by an Ethernet driver.
 */
struct eth_dev_ops {
	eth_dev_configure_t        dev_configure; /**< Configure device. */
	eth_dev_start_t            dev_start;     /**< Start device. */
	eth_dev_stop_t             dev_stop;      /**< Stop device. */
	eth_dev_close_t            dev_close;     /**< Close device. */
	eth_promiscuous_enable_t   promiscuous_enable; /**< Promiscuous ON. */
	eth_promiscuous_disable_t  promiscuous_disable;/**< Promiscuous OFF. */
	eth_allmulticast_enable_t  allmulticast_enable;/**< RX multicast ON. */
	eth_allmulticast_disable_t allmulticast_disable;/**< RX multicast OF. */
	eth_link_update_t          link_update;   /**< Get device link state. */
	eth_stats_get_t            stats_get;     /**< Get device statistics. */
	eth_stats_reset_t          stats_reset;   /**< Reset device statistics. */
	eth_queue_stats_mapping_set_t queue_stats_mapping_set;
	/**< Configure per queue stat counter mapping. */
	eth_dev_infos_get_t        dev_infos_get; /**< Get device info. */
	vlan_filter_set_t          vlan_filter_set;  /**< Filter VLAN Setup. */
	vlan_tpid_set_t            vlan_tpid_set;      /**< Outer VLAN TPID Setup. */
	vlan_strip_queue_set_t     vlan_strip_queue_set; /**< VLAN Stripping on queue. */
	vlan_offload_set_t         vlan_offload_set; /**< Set VLAN Offload. */
	eth_rx_queue_setup_t       rx_queue_setup;/**< Set up device RX queue.*/
	eth_rx_queue_release_t     rx_queue_release;/**< Release RX queue.*/
	eth_tx_queue_setup_t       tx_queue_setup;/**< Set up device TX queue.*/
	eth_tx_queue_release_t     tx_queue_release;/**< Release TX queue.*/
	eth_dev_led_on_t           dev_led_on;    /**< Turn on LED. */
	eth_dev_led_off_t          dev_led_off;   /**< Turn off LED. */
	flow_ctrl_set_t            flow_ctrl_set; /**< Setup flow control. */
	priority_flow_ctrl_set_t   priority_flow_ctrl_set; /**< Setup priority flow control.*/
	eth_mac_addr_remove_t      mac_addr_remove; /**< Remove MAC address */
	eth_mac_addr_add_t         mac_addr_add;  /**< Add a MAC address */
	eth_uc_hash_table_set_t    uc_hash_table_set;  /**< Set Unicast Table Array */
	eth_uc_all_hash_table_set_t uc_all_hash_table_set;  /**< Set Unicast hash bitmap */
	eth_mirror_rule_set_t	   mirror_rule_set;  /**< Add a traffic mirror rule.*/
	eth_mirror_rule_reset_t	   mirror_rule_reset;  /**< reset a traffic mirror rule.*/
	eth_set_vf_rx_mode_t       set_vf_rx_mode;   /**< Set VF RX mode */
	eth_set_vf_rx_t            set_vf_rx;  /**< enable/disable a VF receive */
	eth_set_vf_tx_t            set_vf_tx;  /**< enable/disable a VF transmit */
	eth_set_vf_vlan_filter_t   set_vf_vlan_filter;  /**< Set VF VLAN filter */

	/** Add a signature filter. */
	fdir_add_signature_filter_t fdir_add_signature_filter;
	/** Update a signature filter. */
	fdir_update_signature_filter_t fdir_update_signature_filter;
	/** Remove a signature filter. */
	fdir_remove_signature_filter_t fdir_remove_signature_filter;
	/** Get information about FDIR status. */
	fdir_infos_get_t fdir_infos_get;
	/** Add a perfect filter. */
	fdir_add_perfect_filter_t fdir_add_perfect_filter;
	/** Update a perfect filter. */
	fdir_update_perfect_filter_t fdir_update_perfect_filter;
	/** Remove a perfect filter. */
	fdir_remove_perfect_filter_t fdir_remove_perfect_filter;
	/** Setup masks for FDIR filtering. */
	fdir_set_masks_t fdir_set_masks;
	/** Update redirection table. */
	reta_update_t reta_update;
	/** Query redirection table. */
	reta_query_t reta_query;
};

/**
 * @internal
 * The generic data structure associated with each ethernet device.
 *
 * Pointers to burst-oriented packet receive and transmit functions are
 * located at the beginning of the structure, along with the pointer to
 * where all the data elements for the particular device are stored in shared
 * memory. This split allows the function pointer and driver data to be per-
 * process, while the actual configuration data for the device is shared.
 */
struct rte_eth_dev {
	struct rte_eth_dev_data *data;  /**< Pointer to device data */
	struct eth_dev_ops *dev_ops;    /**< Functions exported by PMD */
	struct pci_dev *pci_dev; /**< PCI info. supplied by probing */
};

struct rte_eth_dev_sriov {
	uint8_t active;               /**< SRIOV is active with 16, 32 or 64 pools */
	uint8_t nb_q_per_pool;        /**< rx queue number per pool */
	uint16_t def_vmdq_idx;        /**< Default pool num used for PF */
	uint16_t def_pool_q_idx;      /**< Default pool queue start reg index */
};
#define RTE_ETH_DEV_SRIOV(dev)         ((dev)->data->sriov)


/**
 * @internal
 * The data part, with no function pointers, associated with each ethernet device.
 *
 * This structure is safe to place in shared memory to be common among different
 * processes in a multi-process configuration.
 */
struct rte_eth_dev_data {
	struct eth_rx_queue **rx_queues; /**< Array of pointers to RX queues. */
	struct eth_tx_queue **tx_queues; /**< Array of pointers to TX queues. */
	struct eth_fg *rx_fgs; /**< An array of flow groups. */
	uint16_t nb_rx_queues; /**< Number of RX queues. */
	uint16_t nb_tx_queues; /**< Number of TX queues. */
	uint16_t max_rx_queues;
	uint16_t max_tx_queues;
	uint16_t nb_rx_fgs;
	
	struct rte_eth_dev_sriov sriov;    /**< SRIOV data */

	void *dev_private;              /**< PMD-specific private data */

	struct rte_eth_link dev_link;
	/**< Link-level information & status */

	struct rte_eth_conf dev_conf;   /**< Configuration applied to device. */

	uint64_t rx_mbuf_alloc_failed; /**< RX ring mbuf allocation failures. */
	struct eth_addr* mac_addrs;/**< Device Ethernet Link address. */
	uint64_t mac_pool_sel[ETH_NUM_RECEIVE_MAC_ADDR]; 
	/** bitmap array of associating Ethernet MAC addresses to pools */
	struct eth_addr* hash_mac_addrs;

	uint32_t max_frame_size;
	/** Device Ethernet MAC addresses of hash filtering. */
	uint8_t port_id;           /**< Device [external] port identifier. */
	uint8_t promiscuous   : 1, /**< RX promiscuous mode ON(1) / OFF(0). */
		scattered_rx : 1,  /**< RX of scattered packets is ON(1) / OFF(0) */
		all_multicast : 1, /**< RX all multicast mode ON(1) / OFF(0). */
		dev_started : 1;   /**< Device state: STARTED(1) / STOPPED(0). */
};

extern void
eth_dev_get_hw_mac(struct rte_eth_dev *dev, struct eth_addr *mac_addr);
extern void eth_dev_set_hw_mac(struct rte_eth_dev *dev, struct eth_addr *mac_addr);
extern struct rte_eth_dev *eth_dev_alloc(size_t private_len);
extern void eth_dev_destroy(struct rte_eth_dev *dev);
extern int eth_dev_add(struct rte_eth_dev *dev);
extern int eth_dev_start(struct rte_eth_dev *dev);
extern void eth_dev_stop(struct rte_eth_dev *dev);
extern int eth_dev_configure(struct rte_eth_dev *dev,
			     const struct rte_eth_conf *conf);
extern int eth_dev_get_rx_queue(struct rte_eth_dev *dev,
				struct eth_rx_queue **rx_queue,
				uint16_t nr_desc,
				struct mbuf_allocator *a);
extern int eth_dev_get_tx_queue(struct rte_eth_dev *dev,
				struct eth_tx_queue **tx_queue,
				uint16_t nr_desc);

extern int ixgbe_create_simple(const struct pci_addr *addr,
			       struct rte_eth_dev **ethp,
			       struct eth_rx_queue **rxp,
			       struct eth_tx_queue **txp,
			       uint16_t rx_desc_nr, uint16_t tx_desc_nr,
			       struct mbuf_allocator *a);
extern void ixgbe_destroy(struct rte_eth_dev *dev);
