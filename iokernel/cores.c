/*
 * cores.c - manages assignments of cores to runtimes, the iokernel, and linux
 */

#include <sched.h>
#include <unistd.h>

#include <base/bitmap.h>
#include <base/cpu.h>
#include <base/hash.h>
#include <base/log.h>
#include <iokernel/queue.h>

#include "defs.h"

unsigned int nr_avail_cores = 0;
DEFINE_BITMAP(avail_cores, NCPU);
struct core_assignments core_assign;
unsigned int nrts = 0;
struct thread *ts[NCPU];

/* maps each cpu number to the number of its hyperthread buddy */
static int cpu_siblings[NCPU];

/**
 * cpu_to_sibling_cpu - gets the sibling (hyperthread pair) of a cpu
 * @cpu: the number of the cpu
 *
 * Returns the number of the sibling cpu.
 */
static inline int cpu_to_sibling_cpu(int cpu)
{
	assert(cpu < cpu_count);
	return cpu_siblings[cpu];
}

/* Stores information about a core. Current is only valid if the core is in
 * use. */
struct core {
	struct thread	*current;
	struct thread	*prev;
};

static struct core core_history[NCPU];

/**
 * core_reserve - record that core is now in use by thread
 * @core: the core to reserve
 * @th: the thread that will use core
 */
static inline void core_reserve(unsigned int core, struct thread *th)
{
	bitmap_clear(avail_cores, core);
	nr_avail_cores--;
	core_history[core].prev = core_history[core].current;
	core_history[core].current = th;
}

/**
 * core_cede - relinquish a core. It no longer has something running on it.
 * @core: the core to relinquish
 */
static inline void core_cede(unsigned int core)
{
	bitmap_set(avail_cores, core);
	nr_avail_cores++;
}

/**
 * core_init - init a core.
 * @core: the core to init
 */
static inline void core_init(unsigned int core)
{
	bitmap_set(avail_cores, core);
	nr_avail_cores++;
	core_history[core].current = NULL;
	core_history[core].prev = NULL;
}

/**
 * core_available - returns true if core is available, false otherwise.
 */
static inline bool core_available(unsigned int core)
{
	return bitmap_test(avail_cores, core);
}

/* a list of procs that currently require more cores */
static LIST_HEAD(overloaded_procs);

/**
 * proc_set_overloaded - marks a process as overloaded
 * p: the process to mark as overloaded
 */
static inline void proc_set_overloaded(struct proc *p)
{
	if (p->overloaded)
		return;

	list_add(&overloaded_procs, &p->overloaded_link);
	p->overloaded = true;
}

/**
 * proc_clear_overloaded - unmarks a process as overloaded
 * @p: the process to unmark as overloaded
 */
static inline void proc_clear_overloaded(struct proc *p)
{
	if (!p->overloaded)
		return;

	list_del_from(&overloaded_procs, &p->overloaded_link);
	p->overloaded = false;
}

/**
 * proc_is_overloaded - returns true if the process is overloaded
 * @p: the process to test if overloaded
 */
static inline bool proc_is_overloaded(struct proc *p)
{
	return p->overloaded;
}

/* a list of procs that are using more cores than they have reserved */
static LIST_HEAD(bursting_procs);

/**
 * proc_set_overloaded - marks a process as bursting
 * p: the process to mark as bursting
 */
static inline void proc_set_bursting(struct proc *p)
{
	if (p->bursting)
		return;

	list_add(&bursting_procs, &p->bursting_link);
	p->bursting = true;
}

/**
 * proc_clear_bursting - unmarks a process as bursting
 * @p: the process to unmark as bursting
 */
static inline void proc_clear_bursting(struct proc *p)
{
	if (!p->bursting)
		return;

	list_del_from(&bursting_procs, &p->bursting_link);
	p->bursting = false;
}

/**
 * proc_is_bursting - returns true if the process is bursting
 * @p: the process to test if bursting
 */
static inline bool proc_is_bursting(struct proc *p)
{
	return p->bursting;
}

/**
 * get_bursting_proc - returns a bursting proc or NULL if none exists
 */
static inline struct proc *get_bursting_proc()
{
	return list_top(&bursting_procs, struct proc, bursting_link);
}

/**
 * thread_reserve - record that thread th will now run on core.
 * @th: the thread to reserve
 * @core: the core this kthread will run on
 */
static inline void thread_reserve(struct thread *th, unsigned int core)
{
	struct proc *p = th->p;
	unsigned int kthread = th - p->threads;

	bitmap_clear(p->available_threads, kthread);
	p->threads[kthread].core = core;
	p->active_threads[p->active_thread_count] = th;
	th->at_idx = p->active_thread_count++;
	list_del_from(&p->idle_threads, &th->idle_link);

	if (p->active_thread_count > p->sched_cfg.guaranteed_cores)
		proc_is_bursting(p);

	proc_clear_overloaded(p);
}

/**
 * thread_cede - relinquish a kthread. It is no longer running on a dedicated
 * core.
 * @th: the thread to relinquish
 */
static inline void thread_cede(struct thread *th)
{
	struct proc *p = th->p;
	unsigned int kthread = th - p->threads;

	bitmap_set(p->available_threads, kthread);
	p->active_threads[th->at_idx] = p->active_threads[--p->active_thread_count];
	p->active_threads[th->at_idx]->at_idx = th->at_idx;
	list_add(&p->idle_threads, &th->idle_link);

	if (p->active_thread_count == p->sched_cfg.guaranteed_cores)
		proc_clear_bursting(p);
}

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
		buf[i] = core_available(i) ? '1' : '0';
	buf[i] = '\0';
	log_debug("cores: %s idle", &buf[0]);
}

/**
 * pick_core_for_proc - choose a core to allocate to proc p.
 * @p: the process to allocate a core to
 *
 * Returns an available core if one exists, or -1 if none are available.
 * TODO: implement better policy, return a core to be preempted instead of -1
 * if none are available.
 */
static inline int pick_core_for_proc(struct proc *p)
{
	int buddy_core, core;
	int i;
	struct thread *t;
	struct proc *buddy_proc, *core_proc;

	/* try to allocate a hyperthread pair core */
	for (i = 0; i < p->active_thread_count; i++) {
		t = p->active_threads[i];
		buddy_core = cpu_to_sibling_cpu(t->core);

		if (core_available(buddy_core))
			return buddy_core;

		if (nr_avail_cores > 0)
			continue;

		buddy_proc = core_history[buddy_core].current->p;
		if (buddy_proc != p && proc_is_bursting(buddy_proc))
			return buddy_core;
	}

	/* try the core that we most recently ran on */
	t = list_top(&p->idle_threads, struct thread, idle_link);
	core = t->core;
	if (core_available(core))
		return core;
	if (nr_avail_cores == 0) {
		core_proc = core_history[core].current->p;
		if (core_proc != p && proc_is_bursting(core_proc))
			return core;
	}

	/* pick the lowest available core */
	core = bitmap_find_next_set(avail_cores, cpu_count, 0);

	if (core == cpu_count) {
		/* no cores available, take from any bursting proc */
		core_proc = get_bursting_proc();
		core = core_proc->active_threads[rand_crc32c((uintptr_t) core_proc)
				% core_proc->active_thread_count]->core;
	}

	return core;
}

/**
 * pick_best_proc_for_core - choose a proc to grant this core to.
 * @core: the core to find a process for
 *
 * Returns a process to grant this core to, or NULL if this core cannot be
 * allocated to any process.
 */
static inline struct proc *pick_proc_for_core(int core)
{
	/* TODO: implement */
	return NULL;
}

/**
 *  pick_thread_for_proc - choose a thread to start up for this proc.
 *  @p: the process to choose a thread for
 *
 *  Returns a struct thread *, or NULL if no thread is idle. This function must
 *  return the 0th index kthread the first time it is called for a proc,
 *  because the first runtime thread is added to the 0th kthread's runqueue and
 *  no kthreads are attached yet, so that thread cannot be stolen.
 */
static inline struct thread *pick_thread_for_proc(struct proc *p)
{
	/* return the most recently parked kthread */
	return list_top(&p->idle_threads, struct thread, idle_link);
}

/**
 * wake_kthread_on_core - choose a kthread for this proc and wake it on the
 * specified core.
 * @p: the process to choose a kthread from
 * @core: the core to wake a kthread on
 */
static struct thread *wake_kthread_on_core(struct proc *p, int core)
{
	struct thread *th;
	int ret;
	ssize_t s;
	uint64_t val = 1;

	BUG_ON(!core_available(core)); /* core should be idle now */

	/* pick a kthread to run on this core */
	th = pick_thread_for_proc(p);
	if (!th) {
		log_err("cores: proc already has max allowed kthreads (%d)",
			p->thread_count);
		BUG();
	}

	/* mark core and kthread as reserved */
	core_reserve(core, th);
	thread_reserve(th, core);

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

/**
 * cores_park_kthread - parks the given kthread and frees its core.
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
		log_err("cores: failed to pin tid %d to linux core %d",
			th->tid, core_assign.linux_core);
		/* continue running but performance is unpredictable */
	}

	/* mark core and kthread as available */
	core_cede(core);
	thread_cede(th);

	/* remove the thread from the polling array (if queues are empty) */
	th->parked = true;
	if (lrpc_empty(&th->txpktq))
		unpoll_thread(th);

	/* try to allocate this core to another proc */
	p = pick_proc_for_core(core);
	if (p)
		wake_kthread_on_core(p, core);
}

/**
 * cores_add_core - allocate a core for this process. If the core is idle, this
 * function immediately wakes a kthread on it. Otherwise, a kthread will be
 * woken on the core once the preempted kthread parks.
 * @p: the process to allocate a core to
 */
struct thread *cores_add_core(struct proc *p)
{
	int core;

	/* pick a core to add */
	core = pick_core_for_proc(p);

	if (core_available(core)) {
		/* core is idle, immediately wake a kthread on it */
		return wake_kthread_on_core(p, core);
	} else {
		/* TODO: core is busy, preempt currently running task */
		log_err("cores: preempting kthreads not yet implemented");
		BUG();
	}
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
	list_head_init(&p->idle_threads);
	for (i = 0; i < p->thread_count; i++) {
		ret = cores_pin_thread(p->threads[i].tid, core_assign.linux_core);
		if (ret < 0) {
			log_err("cores: failed to pin thread %d in cores_init_proc",
					p->threads[i].tid);
			/* continue running but performance is unpredictable */
		}

		/* init core to 0 - this will result in incorrect cache locality
		 * decisions at first but saves us from always checking if this thread
		 * has run yet */
		p->threads[i].core = 0;
		list_add_tail(&p->idle_threads, &p->threads[i].idle_link);
	}

	p->bursting = false;
	p->overloaded = false;

	/* wake the first kthread so the runtime can run the main_fn */
	cores_add_core(p);
}

/*
 * Free cores used by a proc that is exiting.
 */
void cores_free_proc(struct proc *p)
{
	int i;

	proc_clear_bursting(p);
	proc_clear_overloaded(p);

	bitmap_for_each_cleared(p->available_threads, p->thread_count, i)
		cores_park_kthread(&p->threads[i], true);
}

/*
 * Rebalances the allocation of cores to runtimes. Grants more cores to
 * runtimes that would benefit from them.
 */
void cores_adjust_assignments()
{
	struct proc *p, *next;
	struct thread *th;
	uint32_t send_tail, len;
	int i, j;

	/* determine which procs need more cores to meet their guarantees, and
	   which procs want more burstable cores */
	for (i = 0; i < dp.nr_clients; i++) {
		p = dp.clients[i];

		proc_clear_overloaded(p);

		for (j = 0; j < p->active_thread_count; j++) {
			th = p->active_threads[j];

			/* check if runtime is already using max kthreads */
			if (p->active_thread_count == p->thread_count)
				continue;

			/* check if runqueue remained non-empty */
			if (gen_in_same_gen(&th->rq_gen))
				goto request_kthread;

			/* check if rx queue remained non-empty or overflow */
			send_tail = lrpc_poll_send_tail(&th->rxq);
			len = lrpc_get_cached_length(&th->rxq);
			if (len > 0 && (len >= IOKERNEL_RX_WAKE_THRESH ||
						send_tail == th->last_send_tail)) {
				th->last_send_tail = send_tail;
				goto request_kthread;
			}
			th->last_send_tail = send_tail;

			/* TODO: check on timers */

			continue; /* no need to wake a kthread */

		request_kthread:
			if (!proc_is_bursting(p)) {
				if (!cores_add_core(p)) {
					/* we should always have enough cores to
					 * meet guarantees */
					BUG();
				}
			} else
				proc_set_overloaded(p);
			break;
		}
	}

	/* grant cores to procs that are bursting until we run out of cores */
	list_for_each_safe(&overloaded_procs, p, next, overloaded_link) {
		if (nr_avail_cores == 0)
			break;

		if (!cores_add_core(p))
			BUG();
	}
}

/*
 * Initialize core state.
 */
int cores_init(void)
{
	int i, j;

	/* assign first non-zero core on socket 0 to the dataplane thread */
	for (i = 1; i < cpu_count; i++) {
		if (cpu_info_tbl[i].package == 0)
			break;
	}
	if (i == cpu_count)
		panic("cores: couldn't find any cores on package 0");
	core_assign.dp_core = i;

	/* parse hyperthread information */
	for (i = 0; i < cpu_count; i++) {
		int siblings = 0;

		bitmap_for_each_set(cpu_info_tbl[i].thread_siblings_mask,
				    cpu_count, j) {
			if (i == j)
				continue;
			if (siblings++) {
				panic("cores: can't support more than two "
				      "hyperthreads per core.");
			}

			cpu_siblings[i] = j;
		}

		if (siblings == 0)
			panic("cores: must have hyperthreads enabled");
	}

	/* assign the dataplane's sibling to linux and the control thread */
	core_assign.linux_core = cpu_to_sibling_cpu(core_assign.dp_core);
	core_assign.ctrl_core = cpu_to_sibling_cpu(core_assign.dp_core);

	/* mark all cores as unavailable */
	bitmap_init(avail_cores, cpu_count, false);

	/* find cores on socket 0 that are not already in use */
	for (i = 0; i < cpu_count; i++) {
		if (i == core_assign.linux_core ||
		    i == core_assign.ctrl_core ||
		    i == core_assign.dp_core) {
			continue;
		}

		if (cpu_info_tbl[i].package == 0)
			core_init(i);
	}

	log_info("cores: linux on core %d, control on %d, dataplane on %d",
		 core_assign.linux_core, core_assign.ctrl_core,
		 core_assign.dp_core);

	return 0;
}
