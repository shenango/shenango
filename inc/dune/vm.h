/*
 * vm.h - virtual memory management
 */

#pragma once

#include <base/mem.h>
#include <base/page.h>
#include <dune/mmu.h>

#define PGLEVEL_4KB	0
#define PGLEVEL_2MB	1
#define PGLEVEL_1GB	2
#define PGLEVEL_NUM	4

#define PGLEVEL_TO_SIZE(level) (1 << PDSHIFT(level))
#define PGSIZE_TO_LEVEL(size) ((__builtin_ctz(size) - PGSHIFT_4KB) / NPTBITS)


/*
 * Raw Operations
 */

extern int
vm_lookup_pte(ptent_t *tbl, const void *va,
	      int *level_out, ptent_t **pte_out);
extern int
vm_insert_pte(ptent_t *tbl, const void *va,
	      int level, ptent_t pte_in);
extern int
vm_get_pte(ptent_t *tbl, const void *va,
	   int level, ptent_t **pte_out);
extern int
vm_remove_pte(ptent_t *tbl, const void *va,
	      int *level_out, ptent_t *pte_out);


/*
 * Page Operations
 */

extern int
vm_lookup_page(ptent_t *tbl, const void *va, struct page **pg_out);
extern int
vm_insert_page(ptent_t *tbl, const void *va,
	       struct page *pg, ptent_t flags);
extern int
vm_remove_page(ptent_t *tbl, const void *va,
	       struct page **pg_out);


/*
 * Ranged Operations
 */

extern int
vm_map_phys(ptent_t *tbl, physaddr_t pa, const void *va,
	    size_t len, int pgsize, ptent_t flags);
extern int
vm_map_pages(ptent_t *tbl, const void *va, size_t len,
	     int pgsize, ptent_t flags);
extern int
vm_map_copy(ptent_t *tbl, const void *src_va, const void *map_va,
	    size_t len, int pgsize, ptent_t flags);
extern bool
vm_mod(ptent_t *tbl, const void *va, size_t len, int pgsize, ptent_t flags);
extern bool
vm_disable(ptent_t *tbl, const void *va, size_t len, int pgsize);
extern void
vm_unmap(ptent_t *tbl, const void *va, size_t len, int pgsize);
extern void
vm_unmap_pages(ptent_t *tbl, const void *va, size_t len, int pgsize);


/*
 * Page Tables
 */

extern ptent_t *vm_create_pt(void);
extern ptent_t *vm_clone_kern_pt(void);
extern void vm_destroy_pt(ptent_t *tbl);

extern ptent_t *kern_pgtbl;

