/*
 * mem.c - memory management
 */

#include <sys/mman.h>
#include <asm/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <numaif.h>
#include <sys/syscall.h>

#include <base/stddef.h>
#include <base/mem.h>
#include <base/log.h>
#include <base/limits.h>

#if !defined(MAP_HUGE_2MB) || !defined(MAP_HUGE_1GB)
#warning "Your system does not support MAP_HUGETLB page sizes"
#endif

long mbind(void *start, unsigned long len, int mode,
	   const unsigned long *nmask, unsigned long maxnode,
	   unsigned flags)
{
	return syscall(__NR_mbind, start, len, mode, nmask, maxnode, flags);
}

static void sigbus_error(int sig)
{
	panic("couldn't map pages");
}

static void *
__mem_map_anom(void *base, int nr, int size,
	       unsigned long *mask, int numa_policy)
{
	__sighandler_t s;
	void *vaddr;
	int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE;
	size_t len = nr * size;
	int i;

	if (base)
		flags |= MAP_FIXED;

	switch (size) {
	case PGSIZE_4KB:
		break;
	case PGSIZE_2MB:
		flags |= MAP_HUGETLB;
#ifdef MAP_HUGE_2MB
		flags |= MAP_HUGE_2MB;
#endif
		break;
	case PGSIZE_1GB:
#ifdef MAP_HUGE_1GB
		flags |= MAP_HUGETLB | MAP_HUGE_1GB;
#else
		return MAP_FAILED;
#endif
		break;
	default: /* fail on other sizes */
		return MAP_FAILED;
	}

	vaddr = mmap(base, len, PROT_READ | PROT_WRITE, flags, -1, 0);
	if (vaddr == MAP_FAILED)
		return MAP_FAILED;

	BUILD_ASSERT(sizeof(unsigned long) * 8 >= NNUMA);
	if (mbind(vaddr, len, numa_policy, mask ? mask : NULL,
		  mask ? NNUMA : 0, MPOL_MF_STRICT))
		goto fail;

	/*
	 * Unfortunately mmap() provides no error message if MAP_POPULATE fails
	 * because of insufficient memory. Therefore, we manually force a write
	 * on each page to make sure the mapping was successful.
	 */
	s = signal(SIGBUS, sigbus_error);
	for (i = 0; i < nr; i++) {
		*(uint64_t *)((uintptr_t)vaddr + i * size) = 0;
	}
	signal(SIGBUS, s);

	return vaddr;

fail:
	munmap(vaddr, len);
	return MAP_FAILED;
}

/**
 * mem_map_anom - map anonymous memory pages
 * @base: the base address (or NULL for automatic)
 * @nr: the number of pages
 * @size: the page size
 * @node: the NUMA node
 *
 * Returns the base address, or MAP_FAILED if out of memory
 */
void *mem_map_anom(void *base, int nr, int size, int node)
{
	unsigned long mask = (1 << node);
	return __mem_map_anom(base, nr, size, &mask, MPOL_BIND);
}

/**
 * mem_map_file - maps a file into memory
 * @base: the address (or automatic if NULL)
 * @len: the length in bytes
 * @fd: the file descriptor
 * @offset: the offset inside the file
 *
 * Returns the address of the mapping or MAP_FAILED if failure.
 */
void *mem_map_file(void *base, size_t len, int fd, off_t offset)
{
	return mmap(base, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, offset);
}

#define PAGEMAP_PGN_MASK	0x7fffffffffffffULL
#define PAGEMAP_FLAG_PRESENT	(1ULL << 63)
#define PAGEMAP_FLAG_SWAPPED	(1ULL << 62)
#define PAGEMAP_FLAG_FILE	(1ULL << 61)
#define PAGEMAP_FLAG_SOFTDIRTY	(1ULL << 55)

/**
 * mem_lookup_page_phys_addrs - determines the physical address of pages
 * @addr: a pointer to the start of the pages (must be @size aligned)
 * @nr: the number of pages
 * @size: the page size (4KB, 2MB, or 1GB)
 * @paddrs: a pointer store the physical addresses (of @nr elements)
 *
 * Returns 0 if successful, otherwise failure.
 */
int mem_lookup_page_phys_addrs(void *addr, int nr, int size, physaddr_t *paddrs)
{
	int fd, i, ret = 0;
	uint64_t tmp;

	/*
	 * 4 KB pages could be swapped out by the kernel, so it is not
	 * safe to get a machine address. If we later decide to support
	 * 4KB pages, then we need to mlock() the page first.
	 */
	if (size == PGSIZE_4KB)
		return -EINVAL;

	fd = open("/proc/self/pagemap", O_RDONLY);
	if (fd < 0)
		return -EIO;

	for (i = 0; i < nr; i++) {
		if (lseek(fd, (((uintptr_t)addr + (i * size)) /
		    PGSIZE_4KB) * sizeof(uint64_t), SEEK_SET) ==
		    (off_t) -1) {
			ret = -EIO;
			goto out;
		}
		if (read(fd, &tmp, sizeof(uint64_t)) <= 0) {
			ret = -EIO;
			goto out;
		}
		if (!(tmp & PAGEMAP_FLAG_PRESENT)) {
			ret = -ENODEV;
			goto out;
		}

		paddrs[i] = (tmp & PAGEMAP_PGN_MASK) * PGSIZE_4KB;
	}

out:
	close(fd);
	return ret;
}
