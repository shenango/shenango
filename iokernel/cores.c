/*
 * cores.c - manages assignments of cores to runtimes, the iokernel, and linux
 */

#include <sched.h>
#include <unistd.h>

#include <base/bitmap.h>
#include <base/cpu.h>
#include <base/log.h>

#include "defs.h"

DEFINE_BITMAP(avail_cores, NCPU);
struct core_assignments core_assign;

/*
 * Debugging function that logs how each core is currently being used.
 */
static void cores_log_assignments()
{
	int i, j;
	struct proc *p;
	char buf[NCPU+1];

	for (i = 0; i < dp.nr_clients; i++) {
		p = dp.clients[i];

		DEFINE_BITMAP(proc_cores, cpu_count);
		bitmap_init(proc_cores, cpu_count, false);
		bitmap_for_each_cleared(p->available_threads, p->thread_count, j) {
			bitmap_set(proc_cores, p->threads[j].core);
		}

		for (j = 0; j < cpu_count; j++)
			buf[j] = bitmap_test(proc_cores, j) ? '1' : '0';
		buf[j] = '\0';

		log_debug("cores: %s used by runtime pid %d", &buf[0], p->pid);
	}

	for (i = 0; i < cpu_count; i++)
		buf[i] = bitmap_test(avail_cores, i) ? '1' : '0';
	buf[i] = '\0';
	log_debug("cores: %s idle", &buf[0]);
}

/*
 * Parks the given kthread (if it exists) and frees its core.
 */
void cores_park_kthread(struct proc *p, int kthread)
{
	unsigned int core = p->threads[kthread].core;
	int ret;

	/* make sure this core and kthread are currently reserved */
	BUG_ON(bitmap_test(avail_cores, core));
	BUG_ON(bitmap_test(p->available_threads, kthread));

	/* move the kthread to the linux core */
	ret = cores_pin_thread(p->threads[kthread].tid, core_assign.linux_core);
	if (ret < 0 && ret != -ESRCH) {
		/* pinning failed for reason other than tid doesn't exist */
		log_err("cores: failed to pin tid %d to core %d",
				p->threads[kthread].tid, core_assign.linux_core);
		/* continue running but performance is unpredictable */
	}

	/* mark core and kthread as available */
	bitmap_set(avail_cores, core);
	bitmap_set(p->available_threads, kthread);
	p->active_thread_count--;
}

/*
 * Reserves a core for a given proc, returns the index of the kthread assigned
 * to run on it or -1 on error.
 */
int cores_reserve_core(struct proc *p)
{
	unsigned int kthread, core;

	/* pick the lowest available core */
	core = bitmap_find_next_set(avail_cores, cpu_count, 0);
	if (core == cpu_count)
		return -1; /* no cores available */

	/* pick the lowest available kthread */
	kthread = bitmap_find_next_set(p->available_threads, p->thread_count, 0);
	if (kthread == p->thread_count) {
		log_err("cores: proc already has max allowed kthreads (%d)",
				p->thread_count);
		return -1;
	}

	/* mark core and kthread as reserved */
	bitmap_clear(avail_cores, core);
	bitmap_clear(p->available_threads, kthread);
	p->active_thread_count++;
	p->threads[kthread].core = core;

	return kthread;
}

/*
 * Pins the specified kthread for this process to its core and wakes it up.
 */
void cores_wake_kthread(struct proc *p, int kthread)
{
	unsigned int core = p->threads[kthread].core;
	int ret;
	ssize_t s;
	uint64_t val = 1;

	/* make sure the core and kthread have been reserved */
	BUG_ON(bitmap_test(avail_cores, core));
	BUG_ON(bitmap_test(p->available_threads, kthread));

	/* assign the kthread to its core */
	ret = cores_pin_thread(p->threads[kthread].tid, core);
	if (ret < 0) {
		log_err("cores: failed to pin tid %d to core %d",
				p->threads[kthread].tid, core);
		/* continue running but performance is unpredictable */
	}

	/* wake up the kthread */
	s = write(p->threads[kthread].park_efd, &val, sizeof(val));
	BUG_ON(s != sizeof(uint64_t));
}

/*
 * Pins thread tid to core. Returns 0 on success and < 0 on error. Note that
 * this function can always fail with error ESRCH, because threads can be
 * killed at any time.
 */
int cores_pin_thread(pid_t tid, int core)
{
	cpu_set_t cpuset;
	int ret;

	CPU_ZERO(&cpuset);
	CPU_SET(core, &cpuset);

	ret = sched_setaffinity(tid, sizeof(cpu_set_t), &cpuset);
	if (ret < 0) {
		log_warn("cores: failed to set affinity for thread %d with err %d",
				tid, errno);
		return -errno;
	}

	return 0;
}

/*
 * Initialize proc state for managing cores.
 */
void cores_init_proc(struct proc * p)
{
	int i, ret;

	/* all threads are initially pinned to the linux core and will park
	 * themselves immediately */
	p->active_thread_count = 0;
	bitmap_init(p->available_threads, p->thread_count, true);
	for (i = 0; i < p->thread_count; i++) {
		ret = cores_pin_thread(p->threads[i].tid, core_assign.linux_core);
		if (ret < 0) {
			log_err("cores: failed to pin thread %d in cores_init_proc",
					p->threads[i].tid);
			/* continue running but performance is unpredictable */
		}
	}
}

/*
 * Free cores used by a proc that is exiting.
 */
void cores_free_proc(struct proc *p)
{
	int i;

	bitmap_for_each_cleared(p->available_threads, p->thread_count, i)
		cores_park_kthread(p, i);
}

/*
 * Rebalances the allocation of cores to runtimes. Grants more cores to
 * runtimes that would benefit from them.
 * TODO: if all cores are in use, revoke cores from runtimes that are of lower
 * priority.
 */
void cores_adjust_assignments()
{
	int core, i, j, new_kthread;
	struct proc *p;

	/* check for available cores */
	core = bitmap_find_next_set(avail_cores, cpu_count, 0);
	if (core == cpu_count)
		return; /* no cores available */

	for (i = 0; i < dp.nr_clients; i++) {
		p = dp.clients[i];

		/* check if runtime is already using max kthreads */
		if (p->active_thread_count == p->thread_count)
			continue;

		/* if any kthread has been busy over the last interval, wake
		 * another kthread */
		bitmap_for_each_cleared(p->available_threads, p->thread_count, j) {
			/* check if runqueue remained non-empty */
			if (gen_in_same_gen(&p->threads[j].rq_gen))
				goto wake_kthread;

			/* check if rx packet queue has pending packets */
			if (lrpc_get_length(&p->threads[j].rxq) > 0)
				goto wake_kthread;

			/* TODO: check on timers */
		}

		continue; /* no need to wake a kthread */

	wake_kthread:
		new_kthread = cores_reserve_core(p);
		if (new_kthread < 0)
			return; /* no cores available */
		cores_wake_kthread(p, new_kthread);
	}
}

/*
 * Initialize core state.
 */
int cores_init(void)
{
	int i;

	/* assign core 0 to linux and the control thread */
	core_assign.linux_core = 0;
	core_assign.ctrl_core = 0;

	/* assign first non-zero core on socket 0 to the dataplane thread */
	for (i = 1; i < cpu_count; i++) {
		if (cpu_info_tbl[i].package == 0)
			break;
	}
	core_assign.dp_core = i;

	/* mark all cores as unavailable */
	bitmap_init(avail_cores, cpu_count, false);

	/* find cores on socket 0 that are not already in use */
	for (i = 0; i < cpu_count; i++) {
		if (i == core_assign.linux_core || i == core_assign.ctrl_core
				|| i == core_assign.dp_core)
			continue;

		if (cpu_info_tbl[i].package == 0)
			bitmap_set(avail_cores, i);
	}

	log_debug("cores: linux on core %d, control on %d, dataplane on %d",
			core_assign.linux_core, core_assign.ctrl_core,
			core_assign.dp_core);
	bitmap_for_each_set(avail_cores, cpu_count, i)
		log_debug("cores: runtime core: %d", i);

	return 0;
}
