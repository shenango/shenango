/*
 * mempool_completion.c - a dummy mempool whose purpose is to send completion
 * events when tx buffers can be freed
 */

#include <rte_errno.h>
#include <rte_mempool.h>

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
	return n;
}

static int completion_dequeue(struct rte_mempool *mp, void **obj_table, unsigned n)
{
	log_err("mempool_completion: unimplemented function completion_dequeue");
	return n;
}

static unsigned completion_get_count(const struct rte_mempool *mp)
{
	log_err("mempool_completion: unimplemented function completion_get_count");
	return 0;
}

static int completion_alloc(struct rte_mempool *mp)
{
	mp->pool_data = NULL;
	return 0;
}

static void completion_free(struct rte_mempool *mp)
{
	log_err("mempool_completion: unimplemented function completion_free");
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
