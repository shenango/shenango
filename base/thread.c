/*
 * thread.c - support for thread-local storage and initialization
 */

#include <unistd.h>
#include <sched.h>
#include <limits.h>
#include <sys/syscall.h>

#include <base/stddef.h>
#include <base/log.h>
#include <base/cpu.h>
#include <base/thread.h>
#include <base/mem.h>
#include <base/init.h>

void *perthread_offsets[NCPU];
__thread void *perthread_ptr;

__thread unsigned int thread_cpu_id;
__thread unsigned int thread_numa_node;
__thread bool thread_init_done;

extern const char __perthread_start[];
extern const char __perthread_end[];

static int thread_init_perthread(int cpu, int numa_node)
{
	void *addr;
	size_t len = __perthread_end - __perthread_start;

	/* no perthread data */
	if (!len)
		return 0;

	addr = mem_map_anom(NULL, len, PGSIZE_4KB, numa_node);
	if (addr == MAP_FAILED)
		return -ENOMEM;

	memset(addr, 0, len);
	perthread_ptr = addr;
	perthread_offsets[cpu] = addr;
	return 0;
}

/**
 * thread_init_on_core - initializes a thread and binds it to a core
 * @cpu: the CPU to bind the thread to
 *
 * Returns 0 if successful, otherwise fail.
 */
int thread_init_on_core(unsigned int cpu)
{
	int ret;
	cpu_set_t mask;
	unsigned int tmp, numa_node;

	if (cpu >= cpu_count)
		return -EINVAL;

	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	ret = sched_setaffinity(0, sizeof(mask), &mask);
	if (ret)
		return -EPERM;

	ret = syscall(SYS_getcpu, &tmp, &numa_node, NULL);
	if (ret)
		return -ENOSYS;

	if (cpu != tmp) {
		log_err("thread: couldn't migrate to the correct core");
		return -EINVAL;
	}

	ret = thread_init_perthread(cpu, numa_node);
	if (ret)
		return ret;
	if (numa_node >= numa_count) {
		log_err("thread: too many numa nodes\n");
		return -EINVAL;
	}

	thread_cpu_id = cpu;
	thread_numa_node = numa_node;
	log_info("thread: started core %d, numa node %d", cpu, numa_node);
	return 0;
}
