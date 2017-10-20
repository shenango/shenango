/*
 * ethdev.c - ethernet device support
 */

#include <string.h>

#include <base/stddef.h>
#include <base/log.h>
#include <base/lock.h>
#include <base/pci.h>
#include <net/ethernet.h>
#include <net/ethdev.h>

/* TODO: more fine-grained locking */
static DEFINE_SPINLOCK(eth_dev_lock);

/**
 * eth_dev_get_hw_mac - retreives the default MAC address
 * @dev: the ethernet device
 * @mac_addr: pointer to store the mac
 */
void eth_dev_get_hw_mac(struct rte_eth_dev *dev, struct eth_addr *mac_addr)
{
	memcpy(&mac_addr->addr[0], &dev->data->mac_addrs[0], ETH_ADDR_LEN);
}

/**
 * eth_dev_set_hw_mac - sets the default MAC address
 * @dev: the ethernet device
 * @mac_addr: pointer of mac
 */
void eth_dev_set_hw_mac(struct rte_eth_dev *dev, struct eth_addr *mac_addr)
{
	dev->dev_ops->mac_addr_add(dev, mac_addr, 0, 0);
}

static int eth_dev_prepare_start(struct rte_eth_dev *dev)
{
	int ret;
	struct rte_eth_dev_info dev_info;

	dev->dev_ops->dev_infos_get(dev, &dev_info);

	dev->data->nb_rx_queues = 0;
	dev->data->nb_tx_queues = 0;

	dev->data->max_rx_queues =
		min(dev_info.max_rx_queues, ETH_RSS_RETA_MAX_QUEUE);
	dev->data->max_tx_queues = dev_info.max_tx_queues;

	dev->data->rx_queues = malloc(sizeof(struct eth_rx_queue *) *
				      dev->data->max_rx_queues);
	if (!dev->data->rx_queues)
		return -ENOMEM;

	dev->data->tx_queues = malloc(sizeof(struct eth_tx_queue *) *
				      dev->data->max_tx_queues);
	if (!dev->data->tx_queues) {
		ret = -ENOMEM;
		goto err_tx_queues;
	}

	return 0;

err_tx_queues:
	free(dev->data->rx_queues);
	return ret;
}

/**
 * eth_dev_start - starts an ethernet device
 * @dev: the ethernet device
 *
 * Returns 0 if successful, otherwise failure.
 */
int eth_dev_start(struct rte_eth_dev *dev)
{
	int ret;
	struct eth_addr macaddr;
	struct rte_eth_link link;

	ret = eth_dev_prepare_start(dev);
	if (ret)
		return ret;

	ret = dev->dev_ops->dev_start(dev);
	if (ret)
		return ret;

	dev->dev_ops->promiscuous_disable(dev);
	dev->dev_ops->allmulticast_enable(dev);

	eth_dev_get_hw_mac(dev, &macaddr);
	log_info("eth: started an ethernet device\n");
	log_info("eth:\tMAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
		 macaddr.addr[0], macaddr.addr[1],
		 macaddr.addr[2], macaddr.addr[3],
		 macaddr.addr[4], macaddr.addr[5]);

	dev->dev_ops->link_update(dev, 1);
	link = dev->data->dev_link;

	if (!link.link_status) {
		log_warn("eth:\tlink appears to be down, check connection.\n");
	} else {
		log_info("eth:\tlink up - speed %u Mbps, %s\n",
			 (uint32_t)link.link_speed,
			 (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
			 ("full-duplex") : ("half-duplex\n"));
	}

	return 0;
}

/**
 * eth_dev_stop - stops an ethernet device
 * @dev: the ethernet device
 */
void eth_dev_stop(struct rte_eth_dev *dev)
{
	int i;

	dev->dev_ops->dev_stop(dev);

	for (i = 0; i < dev->data->nb_tx_queues; i++)
		dev->dev_ops->tx_queue_release(dev->data->tx_queues[i]);

	for (i = 0; i < dev->data->nb_rx_queues; i++)
		dev->dev_ops->rx_queue_release(dev->data->rx_queues[i]);

	dev->data->nb_rx_queues = 0;
	dev->data->nb_tx_queues = 0;
	free(dev->data->tx_queues);
	free(dev->data->rx_queues);
}

/**
 * eth_dev_get_rx_queue - get the next available rx queue
 * @dev: the ethernet device
 * @rx_queue: pointer to store a pointer to struct eth_rx_queue
 * @nb_desc: the number of descriptor ring entries (must be power of 2)
 * @a: the packet allocator to use for received buffers
 *
 * Returns 0 if successful, otherwise failure.
 */
int eth_dev_get_rx_queue(struct rte_eth_dev *dev,
			 struct eth_rx_queue **rx_queue, uint16_t nb_desc,
			 struct mbuf_allocator *a)
{
	int rx_idx, ret;

	if (!is_power_of_two(nb_desc))
		return -EINVAL;

	spin_lock(&eth_dev_lock);
	rx_idx = dev->data->nb_rx_queues;

	if (rx_idx >= dev->data->max_rx_queues) {
		spin_unlock(&eth_dev_lock);
		return -EMFILE;
	}

	ret = dev->dev_ops->rx_queue_setup(dev, rx_idx, -1, nb_desc, a);
	if (ret) {
		spin_unlock(&eth_dev_lock);
		return ret;
	}

	dev->data->nb_rx_queues++;
	spin_unlock(&eth_dev_lock);

	*rx_queue = dev->data->rx_queues[rx_idx];

	return 0;
}

/**
 * eth_dev_get_tx_queue - get the next available tx queue
 * @dev: the ethernet device
 * @tx_queue: pointer to store a pointer to struct eth_tx_queue
 * @nb_desc: the number of descriptor ring entries (must be power of 2)
 *
 * Returns 0 if successful, otherwise failure.
 */
int eth_dev_get_tx_queue(struct rte_eth_dev *dev,
			 struct eth_tx_queue **tx_queue, uint16_t nb_desc)
{
	int tx_idx, ret;

	if (!is_power_of_two(nb_desc))
		return -EINVAL;

	spin_lock(&eth_dev_lock);
	tx_idx = dev->data->nb_tx_queues;

	if (tx_idx > dev->data->max_tx_queues) {
		spin_unlock(&eth_dev_lock);
		return -EMFILE;
	}

	ret = dev->dev_ops->tx_queue_setup(dev, tx_idx, -1, nb_desc);
	if (ret) {
		spin_unlock(&eth_dev_lock);
		return ret;
	}

	dev->data->nb_tx_queues++;
	spin_unlock(&eth_dev_lock);

	*tx_queue = dev->data->tx_queues[tx_idx];

	return 0;
}

/**
 * eth_dev_alloc - allocates an ethernet device
 * @private_len: the size of the private area
 *
 * Returns an ethernet device, or NULL if failure.
 */
struct rte_eth_dev *eth_dev_alloc(size_t private_len)
{
	struct rte_eth_dev *dev;

	dev = malloc(sizeof(struct rte_eth_dev));
	if (!dev)
		return NULL;

	dev->pci_dev = NULL;
	dev->dev_ops = NULL;

	dev->data = malloc(sizeof(struct rte_eth_dev_data));
	if (!dev->data) {
		free(dev);
		return NULL;
	}

	memset(dev->data, 0, sizeof(struct rte_eth_dev_data));
	dev->data->dev_private = malloc(private_len);
	if (!dev->data->dev_private) {
		free(dev->data);
		free(dev);
		return NULL;
	}

	memset(dev->data->dev_private, 0, private_len);

	return dev;
}

/**
 * eth_dev_destroy - frees an ethernet device
 * @dev: the ethernet device
 */
void eth_dev_destroy(struct rte_eth_dev *dev)
{
	if (dev->dev_ops && dev->dev_ops->dev_close)
		dev->dev_ops->dev_close(dev);

	free(dev->data->dev_private);
	free(dev->data);
	free(dev);
}

/**
 * eth_dev_configure - sets the device configuration
 * @dev: the ethernet device to configure
 * @conf: the configuration parameters to set
 *
 * Returns 0 if successful, otherwise fail.
 */
int eth_dev_configure(struct rte_eth_dev *dev, const struct rte_eth_conf *conf)
{
	dev->data->dev_conf = *conf;
	if (dev->dev_ops && dev->dev_ops->dev_configure)
		return dev->dev_ops->dev_configure(dev);
	return 0;
}

/*
 * Intel 82599 Support (IXGBE)
 * TODO: restructure these helpers to work with other ethernet chipsets.
 * TODO: support more advanced configuration options.
 */

extern int ixgbe_init(struct pci_dev *pci_dev,
		      struct rte_eth_dev **ethp);

static uint8_t rss_key[40];

static const struct rte_eth_conf ixgbe_simple_conf = {
        .rxmode = {
                .split_hdr_size = 0,
                .header_split   = 0, /**< Header Split disabled */
                .hw_ip_checksum = 1, /**< IP checksum offload enabled */
                .hw_vlan_filter = 0, /**< VLAN filtering disabled */
                .jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
                .hw_strip_crc   = 1, /**< CRC stripped by hardware */
                .mq_mode        = ETH_MQ_RX_NONE, /*ETH_MQ_RX_RSS,*/
        },
	.rx_adv_conf = {
		.rss_conf = {
			.rss_hf = ETH_RSS_IPV4_TCP | ETH_RSS_IPV4_UDP,
			.rss_key = rss_key,
		},
	},
        .txmode = {
                .mq_mode = ETH_MQ_TX_NONE,
        },
};

/**
 * ixgbe_create_simple - a simple helper to create an IXGBE ethernet device
 * @addr: the PCI address of the device
 * @ethp: a pointer to store the created ethernet device
 * @rxp: a pointer to store the created RX queue
 * @txp: a pointer to store the created TX queue
 * @rx_desc_nr: the number of RX descriptor ring entries (must be a power of 2)
 * @tx_desc_nr: the nubmer of TX descriptor ring entries (must be a power of 2)
 * @a: the RX mbuf allocator to use
 *
 * This helper creates an ethernet device with a single RX and TX queue, the
 * default hardware MAC, and checksum offloads enabled.
 *
 * Returns 0 if successful, otherwise fail.
 */
int ixgbe_create_simple(const struct pci_addr *addr, struct rte_eth_dev **ethp,
			struct eth_rx_queue **rxp, struct eth_tx_queue **txp,
			uint16_t rx_desc_nr, uint16_t tx_desc_nr,
			struct mbuf_allocator *a)
{
	struct pci_dev *dev;
	struct rte_eth_dev *eth;
	int ret;

	dev = pci_alloc_dev(addr);
	if (!dev)
		return -ENOMEM;

	ret = ixgbe_init(dev, &eth);
	if (!dev) {
		ret = -ENOMEM;
		goto fail_release_pci;
	}

	ret = eth_dev_configure(eth, &ixgbe_simple_conf);
	if (ret)
		goto fail_release_eth;

	ret = eth_dev_get_rx_queue(eth, rxp, rx_desc_nr, a);
	if (ret)
		goto fail_release_eth;

	ret = eth_dev_get_tx_queue(eth, txp, tx_desc_nr);
	if (ret)
		goto fail_release_eth;

	ret = eth_dev_start(eth);
	if (ret)
		goto fail_release_eth;

	*ethp = eth;
	return 0;

fail_release_eth:
	eth_dev_destroy(eth);
fail_release_pci:
	pci_dev_put(dev);
	return ret;
}

/**
 * ixgbe_destroy - tearsdown and frees an IXGBE ethernet device
 * @dev: the ethernet device to destroy
 */
void ixgbe_destroy(struct rte_eth_dev *dev)
{
	eth_dev_stop(dev);
	pci_dev_put(dev->pci_dev);
	eth_dev_destroy(dev);
}
