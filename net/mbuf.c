/*
 * mbuf.c - buffer management for network packets
 */

#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>

#include <base/mempool.h>
#include <base/thread.h>
#include <net/mbuf.h>


/**
 * mbuf_clone - creates an identical copy of an mbuf
 * @a: the allocator to use for the copy
 * @m: the original mbuf to copy
 *
 * Returns a cloned mbuf, or NULL if out or memory or the allocator didn't
 * provide a large enough backing buffer.
 */
struct mbuf *mbuf_clone(struct mbuf_allocator *a, struct mbuf *m)
{
	struct mbuf *new_m;

	if (unlikely(m->head_len > a->head_len))
		return NULL;

	new_m = mbuf_alloc(a);
	if (unlikely(!new_m))
		return NULL;

	/* copy the backing buffer */
	new_m->data = new_m->head + mbuf_headroom(m);
	memcpy(mbuf_put(new_m, mbuf_length(m)), mbuf_data(m), mbuf_length(m));

	/* copy packet metadata */
	new_m->csum_type = m->csum_type;
	new_m->csum = m->csum;
	new_m->txflags = m->txflags; /* NOTE: this is a union */

	return new_m;
}


struct mbuf_mempool {
	struct mbuf_allocator	a;
	struct mempool		m;
	physaddr_t		page_paddrs[];
};

static physaddr_t mbuf_mempool_head_to_paddr(struct mbuf_mempool *p, void *head)
{
	return p->page_paddrs[PGN_2MB((uintptr_t)head - (uintptr_t)p->m.buf)] +
	       PGOFF_2MB(head);
}

static void mbuf_mempool_free(struct mbuf *m)
{
	struct mbuf_mempool *p = (struct mbuf_mempool *)m->release_data;
	mempool_free(&p->m, m);
}

static struct mbuf *mbuf_mempool_alloc(struct mbuf_allocator *a)
{
	struct mbuf_mempool *p = container_of(a, struct mbuf_mempool, a);
	void *item;
	struct mbuf *m;
	unsigned char *head;
	physaddr_t head_paddr;

	item = mempool_alloc(&p->m);
	if (unlikely(!item))
		return NULL;

	m = (struct mbuf *)item;
	head = (unsigned char *)item + sizeof(struct mbuf);
	head_paddr = mbuf_mempool_head_to_paddr(p, head);
	mbuf_init(item, head, p->a.head_len, p->a.reserve_len, head_paddr);
	m->release_data = (unsigned long)p;
	m->release = mbuf_mempool_free;

	return m;
}

static void mbuf_release_mempool_allocator(struct kref *ref)
{
	struct mbuf_mempool *p = container_of(ref, struct mbuf_mempool, a.ref);
	munmap(p->m.buf, p->m.len);
	mempool_destroy(&p->m);
	free(p);
}

/**
 * mbuf_create_mempool_allocator - creates an allocator backed by a mempool
 * mbuf_count: the number of mbuf's in the pool (at least this many)
 * @head_len: the buffer size for each mbuf
 * @reserve_len: the number of bytes to reserve for mbuf buffer
 *
 * Returns an mbuf allocator, or NULL if something went wrong.
 */
struct mbuf_allocator *
mbuf_create_mempool_allocator(size_t mbuf_count, unsigned int head_len,
			      unsigned int reserve_len)
{
	struct mbuf_mempool *p;
	size_t item_size = sizeof(struct mbuf) + head_len;
	size_t nr_pages = div_up(mbuf_count * item_size, PGSIZE_2MB);
	void *buf;
	int ret;

	p = malloc(sizeof(struct mbuf_mempool) + nr_pages * sizeof(physaddr_t));
	if (!p)
		return NULL;

	/* allocate the mempool buffer */
	buf = mem_map_anom(NULL, nr_pages, PGSIZE_2MB, thread_numa_node);
	if (buf == MAP_FAILED)
		goto fail_buf;

	/* get physical page addresses */
	ret = mem_lookup_page_phys_addrs(buf, nr_pages,
					 PGSIZE_2MB, p->page_paddrs);
	if (ret)
		goto fail_phys;

	/* set up the allocator struct */
	p->a.head_len = head_len;
	p->a.reserve_len = reserve_len;
	kref_init(&p->a.ref);
	p->a.alloc = mbuf_mempool_alloc;
	p->a.release = mbuf_release_mempool_allocator;

	/* set up the mempool */
	ret = mempool_create(&p->m, buf, nr_pages * PGSIZE_2MB,
			     PGSIZE_2MB, item_size);
	if (ret)
		goto fail_pool;

	return &p->a;

fail_pool:
fail_phys:
	munmap(buf, nr_pages * PGSIZE_2MB);
fail_buf:
	free(p);
	return NULL;
}
