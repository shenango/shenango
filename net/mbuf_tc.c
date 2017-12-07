/*
 * mbuf_tc.c - mbufs using tcache API
 */

#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>

#include <base/mempool.h>
#include <base/slab.h>
#include <base/tcache.h>
#include <base/thread.h>
#include <net/mbuf.h>

struct mbuf_allocator tc_allocator;

/** buffer allocators **/
static struct mempool	buffer_mempool;
static struct tcache *buffer_tcache;
static __thread struct tcache_perthread buffer_pt;

/** struct mbuf allocators **/
static struct slab mbuf_slab;
static struct tcache *mbuf_tcache;
static __thread struct tcache_perthread mbuf_pt;

void mbuf_tcache_buffer_free(void *buf)
{
	tcache_free(&buffer_pt, buf);
}

static void mbuf_tc_free(struct mbuf *m)
{
	tcache_free(&mbuf_pt, m);
}

static struct mbuf *mbuf_tc_alloc(struct mbuf_allocator *a)
{
	void *buf;
	struct mbuf *m;

	buf = tcache_alloc(&buffer_pt);
	if (unlikely(!buf))
		return NULL;

	m = tcache_alloc(&mbuf_pt);
	if (unlikely(!m)) {
		tcache_free(&buffer_pt, buf);
		return NULL;
	}

	mbuf_init(m, buf, a->head_len, a->reserve_len, 0);
	m->release_data = 0;
	m->release = mbuf_tc_free;

	return m;
}

static void mbuf_release_tcache_allocator(struct kref *ref)
{
	// DO NOTHING
	return;
}

int mbuf_tcache_allocator_init_thread(void)
{
	tcache_init_perthread(mbuf_tcache, &mbuf_pt);
	tcache_init_perthread(buffer_tcache, &buffer_pt);
	return 0;
}

int mbuf_tcache_allocator_init(void *buf, size_t buf_size,
						    size_t mbuf_count,
						    unsigned int head_len,
						    unsigned int reserve_len)
{
	int ret;

	size_t buffers_perpage = PGSIZE_2MB / head_len;
	size_t nr_pages = div_up(mbuf_count, buffers_perpage);

	assert((uintptr_t)buf % PGSIZE_2MB == 0);
	assert(buf_size >= nr_pages * PGSIZE_2MB);

	// Setup buffer pool
	ret = mempool_create(&buffer_mempool, buf, nr_pages * PGSIZE_2MB,
			     PGSIZE_2MB, head_len);
	if (ret)
		goto mempool_fail;

	buffer_tcache = mempool_create_tcache(&buffer_mempool, "buffer pool",
					      TCACHE_DEFAULT_MAG_SIZE);
	if (buffer_tcache == NULL) {
		ret = -ENOMEM;
		goto tcache_fail;
	}


	// Setup mbuf slabs
	ret = slab_create(&mbuf_slab, "struct mbufs", sizeof(struct mbuf), 0);
	if (ret)
		goto slab_fail;

	mbuf_tcache = slab_create_tcache(&mbuf_slab, TCACHE_DEFAULT_MAG_SIZE);
	if (mbuf_tcache == NULL) {
		ret = -ENOMEM;
		goto slab_tc_fail;
	}

	/* set up the allocator struct */
	tc_allocator.head_len = head_len;
	tc_allocator.reserve_len = reserve_len;
	kref_init(&tc_allocator.ref);
	tc_allocator.alloc = mbuf_tc_alloc;
	tc_allocator.release = mbuf_release_tcache_allocator;

	return 0;

slab_tc_fail:
	slab_destroy(&mbuf_slab);
slab_fail:
tcache_fail:
	mempool_destroy(&buffer_mempool);
mempool_fail:
	return ret;

}
