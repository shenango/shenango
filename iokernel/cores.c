/*
 * cores.c - manages assignments of cores to runtimes, the iokernel, and linux
 */

#include <sched.h>
#include <unistd.h>

#include <base/bitmap.h>
#include <base/cpu.h>
#include <base/log.h>
#include <iokernel/queue.h>

#include "defs.h"

DEFINE_BITMAP(avail_cores, NCPU);
struct core_assignments core_assign;
unsigned int nrts = 0;
struct thread *ts[NCPU];

/*
 * Debugging function that logs how each core is currently being used.
 */
__attribute__((unused))
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
 *
 * @th: thread to park
 * @force: true if this kthread should be parked regardless of pending tx pkts
 */
void cores_park_kthread(struct thread *th, bool force)
{
	struct proc *p = th->p;
	unsigned int core = th->core;
	unsigned int kthread = th - p->threads;
	ssize_t s;
	uint64_t val = 1;
	int ret;

	assert(kthread < NCPU);

	/* make sure this core and kthread are currently reserved */
	BUG_ON(bitmap_test(avail_cores, core));
	BUG_ON(bitmap_test(p->available_threads, kthread));

	/* check for race conditions with the runtime */
	lrpc_poll_send_tail(&th->rxq);
	if (unlikely(!force && lrpc_get_cached_length(&th->rxq) > 0)) {
		/* the runtime parked while packets were in flight */
		s = write(th->park_efd, &val, sizeof(val));
		BUG_ON(s != sizeof(uint64_t));
		return;
	}

	/* move the kthread to the linux core */
	ret = cores_pin_thread(th->tid, core_assign.linux_core);
	if (ret < 0 && ret != -ESRCH) {
		/* pinning failed for reason other than tid doesn't exist */
		log_err("cores: failed to pin tid %d to core %d",
			th->tid, core_assign.linux_core);
		/* continue running but performance is unpredictable */
	}

	/* mark core and kthread as available */
	bitmap_set(avail_cores, core);
	bitmap_set(p->available_threads, kthread);
	p->active_threads[th->at_idx] = p->active_threads[--p->active_thread_count];
	p->active_threads[th->at_idx]->at_idx = th->at_idx;

	/* remove the thread from the polling array (if queues are empty) */
	th->parked = true;
	if (lrpc_empty(&th->txpktq))
		unpoll_thread(th);
}

/*
 * Reserves a core for a given proc, returns the index of the kthread assigned
 * to run on it or -1 on error.
 */
static struct thread *cores_reserve_core(struct proc *p)
{
	struct thread *th;
	unsigned int kthread, core;

	/* pick the lowest available core */
	core = bitmap_find_next_set(avail_cores, cpu_count, 0);
	if (core == cpu_count)
		return NULL; /* no cores available */

	/* pick the lowest available kthread */
	kthread = bitmap_find_next_set(p->available_threads, p->thread_count, 0);
	if (kthread == p->thread_count) {
		log_err("cores: proc already has max allowed kthreads (%d)",
			p->thread_count);
		return NULL;
	}

	/* mark core and kthread as reserved */
	th = &p->threads[kthread];
	bitmap_clear(avail_cores, core);
	bitmap_clear(p->available_threads, kthread);
	p->threads[kthread].core = core;
	p->active_threads[p->active_thread_count] = th;
	th->at_idx = p->active_thread_count++;

	return th;
}

/*
 * Wakes a kthread for this process (if one is available).
 */
struct thread *cores_wake_kthread(struct proc *p)
{
	struct thread *th;
	int ret;
	ssize_t s;
	uint64_t val = 1;

	th = cores_reserve_core(p);
	if (!th)
		return NULL;

	/* assign the kthread to its core */
	ret = cores_pin_thread(th->tid, th->core);
	if (unlikely(ret < 0)) {
		log_err("cores: failed to pin tid %d to core %d",
			th->tid, th->core);
		/* continue running but performance is unpredictable */
	}

	/* wake up the kthread */
	s = write(th->park_efd, &val, sizeof(val));
	BUG_ON(s != sizeof(uint64_t));

	/* add the thread to the polling array */
	th->parked = false;
	poll_thread(th);
	return th;
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
void cores_init_proc(struct proc *p)
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

	/* wake the first kthread so the runtime can run the main_fn */
	cores_wake_kthread(p);
}

/*
 * Free cores used by a proc that is exiting.
 */
void cores_free_proc(struct proc *p)
{
	int i;

	bitmap_for_each_cleared(p->available_threads, p->thread_count, i)
		cores_park_kthread(&p->threads[i], true);
}

/*
 * Rebalances the allocation of cores to runtimes. Grants more cores to
 * runtimes that would benefit from them.
 * TODO: if all cores are in use, revoke cores from runtimes that are of lower
 * priority.
 */
void cores_adjust_assignments()
{
	struct thread *th;
	struct proc *p;
	uint32_t send_tail, len;
	int core, i;

	/* check for available cores */
	core = bitmap_find_next_set(avail_cores, cpu_count, 0);
	if (core == cpu_count)
		return; /* no cores available */

	for (i = 0; i < nrts; i++) {
		th = ts[i];
		p = th->p;

		/* check if runtime is already using max kthreads */
		if (p->active_thread_count == p->thread_count)
			continue;

		/* check if runqueue remained non-empty */
		if (gen_in_same_gen(&th->rq_gen))
			goto wake_kthread;

		/* check if rx queue remained non-empty or overflow */
		send_tail = lrpc_poll_send_tail(&th->rxq);
		len = lrpc_get_cached_length(&th->rxq);
		if (len > 0 && (len >= IOKERNEL_RX_WAKE_THRESH ||
				send_tail == th->last_send_tail)) {
			th->last_send_tail = send_tail;
			goto wake_kthread;
		}
		th->last_send_tail = send_tail;

		/* TODO: check on timers */

		continue; /* no need to wake a kthread */

	wake_kthread:
		if (!cores_wake_kthread(p))
			break;

		/*
		 * TODO: temporary hack. Wake just one thread. In reality, we
		 * want to wake one thread per process but still waiting for
		 * some infrastructure code first.
		 */
		break;
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
