/*
 * mbuf_tc.c - mbufs using tcache API
 */

#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>

#include <base/mempool.h>
#include <base/tcache.h>
#include <base/thread.h>
#include <net/mbuf.h>

struct mbuf_allocator tc_allocator;
static DEFINE_SPINLOCK(mempool_lock);
static struct mempool	tc_mempool;
static physaddr_t *page_paddrs;
static struct tcache *mbuf_tcache;
static __thread struct tcache_perthread mbuf_pt;


static void mbuf_tcache_free(struct tcache *tc, int nr, void **items)
{
	int i;

	spin_lock(&mempool_lock);
	for (i = 0; i < nr; i++) {
		mempool_free(&tc_mempool, items[i]);
	}
	spin_unlock(&mempool_lock);
}

static int mbuf_tcache_alloc(struct tcache *tc, int nr, void **items)
{
	int i;

	spin_lock(&mempool_lock);
	for (i = 0; i < nr; i++) {
		items[i] = mempool_alloc(&tc_mempool);
		if (items[i] == NULL) {
			spin_unlock(&mempool_lock);
			mbuf_tcache_free(tc, i, items);
			return -ENOMEM;
		}
	}
	spin_unlock(&mempool_lock);
	return 0;
}

static const struct tcache_ops mbuf_tcache_ops = {
    .alloc = mbuf_tcache_alloc, .free = mbuf_tcache_free,
};

static void mbuf_tc_mempool_free(struct mbuf *m)
{
	tcache_free(&mbuf_pt, m);
}

static struct mbuf *mbuf_tc_mempool_alloc(struct mbuf_allocator *a)
{
	void *item;
	struct mbuf *m;
	unsigned char *head;
	physaddr_t head_paddr;

	item = tcache_alloc(&mbuf_pt);
	if (unlikely(!item))
		return NULL;

	m = (struct mbuf *)item;
	head = (unsigned char *)item + sizeof(struct mbuf);

	head_paddr =
	    page_paddrs[PGN_2MB((uintptr_t)head - (uintptr_t)tc_mempool.buf)] +
	    PGOFF_2MB(head);

	mbuf_init(item, head, a->head_len, a->reserve_len, head_paddr);
	m->release_data = 0;
	m->release = mbuf_tc_mempool_free;

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
	return 0;
}

int mbuf_tcache_allocator_init(void *buf, size_t buf_size,
						    size_t mbuf_count,
						    unsigned int head_len,
						    unsigned int reserve_len)
{
	int ret;
	size_t item_size = sizeof(struct mbuf) + head_len;
	size_t nr_pages = div_up(mbuf_count * item_size, PGSIZE_2MB);

	// Setup mempool
	assert((uintptr_t)buf % PGSIZE_2MB == 0);
	assert(buf_size >= nr_pages * PGSIZE_2MB);
	ret = mempool_create(&tc_mempool, buf, nr_pages * PGSIZE_2MB,
			     PGSIZE_2MB, item_size);
	if (ret)
		goto mempool_fail;

	// Get physical page addresses
	page_paddrs = malloc(sizeof(*page_paddrs) * nr_pages);
	if (page_paddrs == NULL)
		goto phys_alloc_fail;
	ret =
	    mem_lookup_page_phys_addrs(buf, nr_pages, PGSIZE_2MB, page_paddrs);
	if (ret)
		goto phys_fail;

	// Setup tcache
	mbuf_tcache = tcache_create("mbufs", &mbuf_tcache_ops,
				    TCACHE_DEFAULT_MAG_SIZE, item_size);
	if (mbuf_tcache == NULL)
		goto tcache_fail;

	/* set up the allocator struct */
	tc_allocator.head_len = head_len;
	tc_allocator.reserve_len = reserve_len;
	kref_init(&tc_allocator.ref);
	tc_allocator.alloc = mbuf_tc_mempool_alloc;
	tc_allocator.release = mbuf_release_tcache_allocator;

	return 0;

tcache_fail:
phys_fail:
	free(page_paddrs);
phys_alloc_fail:
	mempool_destroy(&tc_mempool);
mempool_fail:
	return -ENOMEM;

}
