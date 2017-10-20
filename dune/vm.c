/*
 * vm.h - virtual memory management support
 */

#include <string.h>

#include <base/stddef.h>
#include <base/mem.h>
#include <base/page.h>
#include <dune/vm.h>

#define PTE_DEF_FLAGS	CAST64(PTE_P | PTE_W | PTE_U)
#define PTE_PERM_FLAGS	CAST64(PTE_P | PTE_W | PTE_NX | PTE_U)
#define PTE_COW_FLAGS	CAST64(PTE_P | PTE_NX | PTE_U)

static bool pte_present(ptent_t e)
{
	return (PTE_FLAGS(e) & PTE_P) > 0;
}

static bool pte_big(ptent_t e)
{
	return (PTE_FLAGS(e) & PTE_PS) > 0;
}

static bool addr_is_aligned(const void *addr, int pgsize)
{
	return !((uintptr_t)addr & (pgsize - 1));
}

static bool addr_is_aligned_to_level(const void *addr, int level)
{
	return addr_is_aligned(addr, PGLEVEL_TO_SIZE(level));
}

static struct page *vm_alloc_pgdir(void)
{
	struct page *pg = page_zalloc(PGSIZE_4KB);
	if (unlikely(!pg))
		return NULL;

	pg->flags |= PAGE_FLAG_PGDIR;
	pg->item_count = 0;
	return pg;
}

/**
 * vm_lookup_pte - looks up a page table entry
 * @tbl: the page table
 * @va: the virtual address
 * @level_out: a pointer to store the page level
 * @pte_out: a pointer to store the PTE pointer
 *
 * WARNING: Synchronization not provided...
 *
 * Returns 0 if successful, otherwise fail.
 */
int vm_lookup_pte(ptent_t *tbl, const void *va, int *level_out,
		  ptent_t **pte_out)
{
	ptent_t *pte = tbl;
	int level;

	for (level = PGLEVEL_NUM - 1; level >= 0; level--) {
		pte = &pte[PDX(level, va)];
		if (!*pte)
			return -ENOENT;
		if (!level || (level <= PGLEVEL_1GB && pte_big(*pte)))
			break;

		pte = (ptent_t *)PTE_ADDR(*pte);
	}

	if (!addr_is_aligned_to_level(va, level))
		return -EINVAL;

	if (level_out)
		*level_out = level;
	if (pte_out)
		*pte_out = pte;

	return 0;
}

/**
 * vm_insert_pte - inserts an entry into the page table
 * @tbl: the page table
 * @va: the virtual address
 * @level: the level to insert the pte
 * @pte_in: the pte to insert
 *
 * WARNING: Synchronization is not provided.
 *
 * Returns 0 if successful, otherwise fail.
 */
int vm_insert_pte(ptent_t *tbl, const void *va, int level, ptent_t pte_in)
{
	ptent_t *hist[PGLEVEL_NUM];
	ptent_t *pte = tbl;
	struct page *pg;
	int pos;

	if (level < PGLEVEL_4KB || level >= PGLEVEL_NUM)
		return -EINVAL;
	if (!(pte_in & PTE_PS) && level > PGLEVEL_4KB)
		return -EINVAL;
	if (!addr_is_aligned_to_level(va, level))
		return -EINVAL;

	for (pos = PGLEVEL_NUM - 1; pos > level; pos--) {
		pte = &pte[PDX(pos, va)];
		hist[pos] = pte;

		if (!*pte) {
			addr_to_smpage(pte)->item_count++;
			pg = vm_alloc_pgdir();
			if (unlikely(!pg))
				goto fail;

			*pte = (ptent_t)smpage_to_addr(pg) | PTE_DEF_FLAGS;
		} else if (pos <= PGLEVEL_1GB && pte_big(*pte)) {
			return -EEXIST;
		}

		pte = (ptent_t *)PTE_ADDR(*pte);
	}

	pte = &pte[PDX(level, va)];
	if (unlikely(*pte))
		return -EEXIST;

	addr_to_smpage(pte)->item_count++;
	*pte = pte_in;
	return 0;


fail:
	for (; pos < PGLEVEL_NUM; pos++) {
		*hist[pos] = 0;
		pg = addr_to_smpage(hist[pos]);
		if (!--pg->item_count)
			break;

		page_put(pg);
	}

	return -ENOMEM;
}

/**
 * vm_remove_pte - removes an entry from the page table
 * @tbl: the page table
 * @va: the virtual address
 * @level_out: a pointer to store the page level
 * @pte_out: a pointer to store the pte value
 *
 * WARNING: Synchronization is not provided.
 *
 * Returns 0 if successful, otherwise -ENOENT if nothing to remove.
 */
int vm_remove_pte(ptent_t *tbl, const void *va,
		  int *level_out, ptent_t *pte_out)
{
	ptent_t *hist[PGLEVEL_NUM];
	ptent_t *pte = tbl;
	struct page *pg;
	int level;

	for (level = PGLEVEL_NUM - 1; level >= PGLEVEL_4KB; level--) {
		pte = &pte[PDX(level, va)];
		hist[level] = pte;
		if (!*pte)
			return -ENOENT;
		if (!level || (level <= PGLEVEL_1GB && pte_big(*pte)))
			break;

		pte = (ptent_t *)PTE_ADDR(*pte);
	}

	if (!addr_is_aligned_to_level(va, level))
		return -EINVAL;

	if (level_out)
		*level_out = level;
	if (pte_out)
		*pte_out = *pte;

	for (; level < PGLEVEL_NUM; level++) {
		pg = addr_to_smpage(hist[level]);
		*hist[level] = 0;
		if (!--pg->item_count)
			break;

		page_put(pg);
	}

	return 0;
}

/**
 * vm_lookup_page - gets the page mapped at a virtual address
 * @tbl: the page table
 * @va: the virtual address
 * @pg_out: the page to get
 *
 * WARNING: Sychronization is not provided.
 *
 * Returns a struct page, or NULL if none was mapped.
 */
int vm_lookup_page(ptent_t *tbl, const void *va, struct page **pg_out)
{
	int ret;
	ptent_t *pte;

	ret = vm_lookup_pte(tbl, va, NULL, &pte);
	if (ret)
		return ret;

	assert(*pte & PTE_PAGE);
	*pg_out = addr_to_page((void *)PTE_ADDR(*pte));
	return 0;
}

/**
 * vm_insert_page - inserts a page at a virtual address
 * @tbl: the page table
 * @va: the virtual address
 * @pg: the page to insert
 * @flags: the PTE flags
 *
 * WARNING: Synchronization is not provided.
 * The caller is responsible for incrementing the page refcount.
 *
 * Returns 0 if successful, otherwise fail.
 */
int vm_insert_page(ptent_t *tbl, const void *va, struct page *pg, ptent_t flags)
{
	int ret;
	ptent_t pte;
	bool large = (pg->flags & PAGE_FLAG_LARGE) > 0;

	pte = (ptent_t)smpage_to_addr(pg) | flags | PTE_PAGE;
	if (large)
		pte |= PTE_PS;

	ret = vm_insert_pte(tbl, va, large ? PGLEVEL_2MB : PGLEVEL_4KB, pte);
	return ret;
}

/**
 * vm_remove_page - removes a page at a virtual address
 * @tbl: the page table
 * @va: the virtual address
 * @pg_out: a pointer to store the removed page (can be NULL)
 *
 * WARNING: Synchronization is not provided.
 * The caller is responsible for dropping the page refcount.
 *
 * Returns 0 if successful, or -ENOENT if there wasn't a page mapped.
 */
int vm_remove_page(ptent_t *tbl, const void *va, struct page **pg_out)
{
	int ret;
	ptent_t pte;

	ret = vm_remove_pte(tbl, va, NULL, &pte);
	if (ret)
		return ret;

	assert(pte & PTE_PAGE);
	if (pg_out)
		*pg_out = addr_to_page((void *)PTE_ADDR(pte));
	return 0;
}

/**
 * vm_map_phys - maps a range of physical memory to a range of virtual addresses
 * @tbl: the page table
 * @pa: the starting physical address
 * @va: the starting virtual address
 * @len: the length of the mapping (in bytes)
 * @pgsize: the page size to use for the mappings
 * @flags: the PTE flags
 *
 * WARNING: Synchronization is not provided.
 *
 * Returns 0 if successful, otherwise fail.
 */
int vm_map_phys(ptent_t *tbl, physaddr_t pa, const void *va,
		size_t len, int pgsize, ptent_t flags)
{
	intptr_t pos;
	int ret;

	if (unlikely(!addr_is_aligned(va, pgsize)))
		return -EINVAL;

	if (pgsize > PGSIZE_4KB)
		flags |= PTE_PS;

	for (pos = 0; pos < len; pos += pgsize) {
		ptent_t pte = PTE_FLAGS(flags) | PTE_ADDR(pa + pos);

		ret = vm_insert_pte(tbl, va + pos,
				    PGSIZE_TO_LEVEL(pgsize), pte);
		if (unlikely(ret))
			goto fail;
	}

	return 0;

fail:
	for (pos -= pgsize; pos >= 0; pos -= pgsize)
		vm_remove_pte(tbl, va + pos, NULL, NULL);
	return ret;
}

/**
 * vm_map_pages - maps pages to a range of virtual addresses
 * @tbl: the pgae table
 * @va: the starting virtual address
 * @len: the length of the mapping (in bytes)
 * @pgsize: the page size to use for the mappings
 * @flags: the PTE flags
 *
 * WARNING: Synchronization is not provided.
 *
 * Returns 0 if successful, otherwise fail.
 */
int vm_map_pages(ptent_t *tbl, const void *va, size_t len,
		 int pgsize, ptent_t flags)
{
	const char *start = (const char *)va;
	intptr_t pos;
	int ret;

	if (unlikely(pgsize != PGSIZE_4KB && pgsize != PGSIZE_2MB))
		return -EINVAL;
	if (unlikely(!addr_is_aligned(va, pgsize)))
		return -EINVAL;

	for (pos = 0; pos < len; pos += pgsize) {
		struct page *pg = page_zalloc(pgsize);
		if (unlikely(!pg))
			goto fail;

		ret = vm_insert_page(tbl, start + pos, pg, flags);
		if (unlikely(ret)) {
			page_put(pg);
			goto fail;
		}
	}

	return 0;

fail:
	for (pos -= pgsize; pos >= 0; pos -= pgsize) {
		struct page *pg;
		if (!vm_remove_page(tbl, start + pos, &pg))
			page_put(pg);
	}

	return ret;
}

/**
 * vm_map_copy - copies memory to new pages for a range of virtual addresses
 * @tbl: the page table
 * @src_va: the source data (from the current page table)
 * @map_va: the destination address (in page table @tbl)
 * @len: the length to copy
 * @pgsize: the page size
 * @flags: the PTE flags
 *
 * WARNING: Synchronization is not provided.
 *
 * Returns 0 if successful, otherwise fail.
 */
int vm_map_copy(ptent_t *tbl, const void *src_va, const void *map_va,
		size_t len, int pgsize, ptent_t flags)
{
	const char *src_start = (const char *)src_va;
	const char *map_start = (const char *)map_va;
	intptr_t pos;
	int ret;

	if (unlikely(pgsize != PGSIZE_4KB && pgsize != PGSIZE_2MB))
		return -EINVAL;
	if (unlikely(!addr_is_aligned(map_va, pgsize)))
		return -EINVAL;

	for (pos = 0; pos < len; pos += pgsize) {
		struct page *pg = page_alloc(pgsize);
		if (unlikely(!pg))
			goto fail;

		memcpy(page_to_addr(pg), src_start + pos,
		       min(pgsize, len - pos));
		ret = vm_insert_page(tbl, map_start + pos, pg, flags);
		if (unlikely(ret)) {
			page_put(pg);
			goto fail;
		}
	}

	return 0;

fail:
	for (pos -= pgsize; pos >= 0; pos -= pgsize) {
		struct page *pg;
		if (!vm_remove_page(tbl, map_start + pos, &pg))
			page_put(pg);
	}

	return ret;
}

/**
 * vm_mod - changes the PTE flags for a range of virtual addresses
 * @tbl: the page table
 * @va: the starting virtual address
 * @len: the length of the range (in bytes)
 * @pgsize: the smallest possible page size
 * @flags: the new PTE flags
 *
 * Will silently skip missing mappings.
 *
 * Returns true if one or more PTE permissions were changed, otherwise false.
 */
bool vm_mod(ptent_t *tbl, const void *va, size_t len, int pgsize, ptent_t flags)
{
	const char *start = (const char *) va;
	intptr_t pos;
	int ret, level;
	bool changed = false;

	/* check alignment */
	assert(addr_is_aligned(va, pgsize));

	for (pos = 0; pos < len;) {
		ptent_t *pte;
		ptent_t old;

		ret = vm_lookup_pte(tbl, start + pos, &level, &pte);
		if (ret) {
			pos += pgsize;
			continue;
		}

		old = *pte;
		*pte &= ~(PTE_PERM_FLAGS);
		if (old & PTE_COW)
			*pte |= (flags & PTE_COW_FLAGS);
		else
			*pte |= (flags & PTE_PERM_FLAGS);
		if (*pte != old)
			changed = true;

		assert(pgsize <= PGLEVEL_TO_SIZE(level));
		pos += PGLEVEL_TO_SIZE(level);
	}

	return changed;
}

/**
 * vm_disable - marks a range of PTEs not present
 * @tbl: the page table
 * @va: the starting virtual address
 * @len: the length of the range (in bytes)
 * @pgsize: the smallest possible page size
 *
 * Will silently skip missing mappings.
 *
 * Returns true if one or more PTEs were disabled, otherwise false.
 */
bool vm_disable(ptent_t *tbl, const void *va, size_t len, int pgsize)
{
	const char *start = (const char *) va;
	intptr_t pos;
	int ret, level;
	bool changed = false;

	/* check alignment */
	assert(addr_is_aligned(va, pgsize));

	for (pos = 0; pos < len;) {
		ptent_t *pte;

		ret = vm_lookup_pte(tbl, start + pos, &level, &pte);
		if (ret) {
			pos += pgsize;
			continue;
		}

		*pte &= ~(CAST64(PTE_P));
		assert(pgsize <= PGLEVEL_TO_SIZE(level));
		pos += PGLEVEL_TO_SIZE(level);
		changed = true;
	}

	return changed;
}

/**
 * vm_unmap - removes mappings from a range of virtual addresses
 * @tbl: the page table
 * @va: the starting virtual address
 * @len: the length of the range (in bytes)
 * @pgsize: the smallest possible page size
 *
 * Use this variant for mappings that are not backed by pages.
 *
 * Cannot fail, but may skip missing mappings.
 */
void vm_unmap(ptent_t *tbl, const void *va, size_t len, int pgsize)
{
	uintptr_t pos;
	int ret, level;

	/* check alignment */
	assert(addr_is_aligned(va, pgsize));

	for (pos = 0; pos < len;) {
		ret = vm_remove_pte(tbl, va + pos, &level, NULL);
		if (ret) {
			pos += pgsize;
		} else {
			assert(pgsize <= PGLEVEL_TO_SIZE(level));
			pos += PGLEVEL_TO_SIZE(level);
		}
	}
}

/**
 * vm_unmap_pages - removes pages from a range of virtual addresses
 * @tbl: the page table
 * @va: the starting virtual address
 * @len: the length of the range (in bytes)
 * @pgsize: the smallest possible page size
 *
 * Use this variant for mappings backed by pages (does ref counting).
 *
 * Cannot fail, but may skip missing mappings.
 */
void vm_unmap_pages(ptent_t *tbl, const void *va, size_t len, int pgsize)
{
	intptr_t pos;

	/* check alignment */
	assert(addr_is_aligned(va, pgsize));

	for (pos = 0; pos < len;) {
		struct page *pg;
		if (!vm_remove_page(tbl, va + pos, &pg)) {
			assert(pgsize <= page_to_size(pg));
			pos += page_to_size(pg);
			page_put(pg);
		} else
			pos += pgsize;
	}
}

/**
 * vm_create_pt - creates a page table
 *
 * Returns a page table, or NULL if out of memory.
 */
ptent_t *vm_create_pt(void)
{
	struct page *pg = vm_alloc_pgdir();
	if (!pg)
		return NULL;

	return (ptent_t *)smpage_to_addr(pg);
}

/**
 * vm_clone_kern_pt - creates a copy of the kernel page table
 *
 * WARNING: Pages in the kernel page table won't be refcounted. It's assumed
 * they are never deallocated for the life of the process.
 *
 * Returns a page table, or NULL if out of memory.
 */
ptent_t *vm_clone_kern_pt(void)
{
	int i, j, k, l;
	struct page *pg;
	ptent_t *src_pud, *src_pmd, *src_pd;
	ptent_t *dst_pud, *dst_pmd, *dst_pd;
	ptent_t *pgtbl = vm_create_pt();
	if (unlikely(!pgtbl))
		return NULL;

	for (i = 0; i < NPTENTRIES; i++) {
		if (!pte_present(kern_pgtbl[i]))
			continue;

		pg = vm_alloc_pgdir();
		if (unlikely(!pg))
			goto err;

		src_pud = (ptent_t *)PTE_ADDR(kern_pgtbl[i]);
		dst_pud = (ptent_t *)smpage_to_addr(pg);
		pgtbl[i] = (ptent_t)dst_pud | PTE_DEF_FLAGS;
		addr_to_smpage(pgtbl)->item_count++;

		for (j = 0; j < NPTENTRIES; j++) {
			if (!src_pud[j])
				continue;
			if (pte_big(src_pud[j])) {
				assert(!(src_pud[j] & PTE_PAGE));
				dst_pud[j] = src_pud[j];
				pg->item_count++;
				continue;
			}

			pg = vm_alloc_pgdir();
			if (unlikely(!pg))
				goto err;

			src_pmd = (ptent_t *)PTE_ADDR(src_pud[j]);
			dst_pmd = (ptent_t *)smpage_to_addr(pg);
			dst_pud[j] = (ptent_t)dst_pmd | PTE_DEF_FLAGS;
			addr_to_smpage(dst_pud)->item_count++;

			for (k = 0; k < NPTENTRIES; k++) {
				if (!src_pmd[k])
					continue;
				if (pte_big(src_pmd[k])) {
					dst_pmd[k] = src_pmd[k];
					pg->item_count++;
					continue;
				}

				pg = vm_alloc_pgdir();
				if (unlikely(!pg))
					goto err;

				src_pd = (ptent_t *)PTE_ADDR(src_pmd[k]);
				dst_pd = (ptent_t *)smpage_to_addr(pg);
				dst_pmd[k] = (ptent_t)smpage_to_addr(pg) |
					     PTE_DEF_FLAGS;
				addr_to_smpage(dst_pmd)->item_count++;

				for (l = 0; l < NPTENTRIES; l++) {
					dst_pd[l] = src_pd[l];
					pg->item_count++;
				}
			}
		}
	}

	return pgtbl;

err:
	vm_destroy_pt(pgtbl);
	return NULL;
}

/**
 * vm_destroy_pt - destroys a page table
 * @tbl: the page table
 */
void vm_destroy_pt(ptent_t *tbl)
{
	int i, j, k;
	ptent_t *pud, *pmd;

	for (i = 0; i < NPTENTRIES; i++) {
		if (!pte_present(tbl[i]))
			continue;

		pud = (ptent_t *)PTE_ADDR(tbl[i]);

		for (j = 0; j < NPTENTRIES; j++) {
			if (!pud[j])
				continue;
			if (pte_big(pud[j]))
				continue;

			pmd = (ptent_t *)PTE_ADDR(pud[j]);

			for (k = 0; k < NPTENTRIES; k++) {
				if (!pmd[k])
					continue;
				if (pte_big(pmd[k]))
					continue;

				page_put_addr((ptent_t *)PTE_ADDR(pmd[k]));
			}

			page_put_addr(pmd);
		}

		page_put_addr(pud);
	}

	page_put_addr(tbl);
}
