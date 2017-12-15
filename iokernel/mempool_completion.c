/*
 * mempool_completion.c - a single producer, single consumer mempool that sends
 * completion events when tx buffers can be freed. Based on rte_mempool_ring.c.
 */

#include <rte_errno.h>
#include <rte_mempool.h>
#include <rte_ring.h>

#include <base/log.h>

#include "defs.h"

static int completion_enqueue(struct rte_mempool *mp, void * const *obj_table,
		unsigned n)
{
	unsigned i;

	for (i = 0; i < n; i++) {
		if (!dpdk_send_completion(obj_table[i]))
			return -ENOBUFS;
	}

	return rte_ring_sp_enqueue_bulk(mp->pool_data, obj_table, n, NULL) == 0 ?
			-ENOBUFS : 0;
}

static int completion_dequeue(struct rte_mempool *mp, void **obj_table, unsigned n)
{
	return rte_ring_sc_dequeue_bulk(mp->pool_data, obj_table, n, NULL) == 0 ?
			-ENOBUFS : 0;
}

static unsigned completion_get_count(const struct rte_mempool *mp)
{
	return rte_ring_count(mp->pool_data);
}

static int completion_alloc(struct rte_mempool *mp)
{
	int ret, rg_flags;
	char rg_name[RTE_RING_NAMESIZE];
	struct rte_ring *r;

	ret = snprintf(rg_name, sizeof(rg_name), RTE_MEMPOOL_MZ_FORMAT, mp->name);
	if (ret < 0 || ret >= (int) sizeof(rg_name)) {
		rte_errno = ENAMETOOLONG;
		return -rte_errno;
	}

	/* ring flags */
	rg_flags = RING_F_SP_ENQ | RING_F_SC_DEQ;

	/* allocate the ring that will be used to store objects */
	r = rte_ring_create(rg_name, rte_align32pow2(mp->size + 1), mp->socket_id,
			rg_flags);
	if (r == NULL)
		return -rte_errno;

	mp->pool_data = r;

	return 0;
}

static void completion_free(struct rte_mempool *mp)
{
	rte_ring_free(mp->pool_data);
}

/*
 * Dummy mempool that sends completion events on enqueue and does nothing else.
 */
static const struct rte_mempool_ops ops_completion = {
	.name = "completion",
	.alloc = completion_alloc,
	.free = completion_free,
	.enqueue = completion_enqueue,
	.dequeue = completion_dequeue,
	.get_count = completion_get_count,
};

MEMPOOL_REGISTER_OPS(ops_completion);
