/*
 * init.c - initializes the runtime
 */

#include <pthread.h>

#include <base/cpu.h>
#include <base/init.h>
#include <base/log.h>
#include <base/limits.h>
#include <runtime/thread.h>

#include "defs.h"

struct init_entry {
	const char *name;
	int (*init)(void);
};

#define GLOBAL_INITIALIZER(name) \
	{__cstr(name), &name ## _init}

/* global subsystem initialization */
static const struct init_entry global_init_handlers[] = {
	/* runtime core */
	GLOBAL_INITIALIZER(stack),
	GLOBAL_INITIALIZER(sched),

	/* network stack */
	GLOBAL_INITIALIZER(net),
	GLOBAL_INITIALIZER(arp),
	GLOBAL_INITIALIZER(udp),
};

#define THREAD_INITIALIZER(name) \
	{__cstr(name), &name ## _init_thread}

/* per-kthread subsystem initialization */
static const struct init_entry thread_init_handlers[] = {
	/* runtime core */
	THREAD_INITIALIZER(kthread),
	THREAD_INITIALIZER(ioqueues),
	THREAD_INITIALIZER(stack),
	THREAD_INITIALIZER(timer),
	THREAD_INITIALIZER(sched),

	/* network stack */
	THREAD_INITIALIZER(net),
};

#define LATE_INITIALIZER(name) \
	{__cstr(name), &name ## _init_late}

static const struct init_entry late_init_handlers[] = {
	/* network stack */
	LATE_INITIALIZER(arp),
	LATE_INITIALIZER(stat),
};

static int run_init_handlers(const char *phase,
			     const struct init_entry *h, int nr)
{
	int i, ret;

	log_debug("entering '%s' init phase", phase);
	for (i = 0; i < nr; i++) {
		log_debug("init -> %s", h[i].name);
		ret = h[i].init();
		if (ret) {
			log_debug("failed, ret = %d", ret);
			return ret;
		}
	}

	return 0;
}

static int runtime_init_thread(void)
{
	int ret;

	ret = base_init_thread();
	if (ret) {
		log_err("base library per-thread init failed, ret = %d", ret);
		return ret;
	}

	return run_init_handlers("per-thread", thread_init_handlers,
				 ARRAY_SIZE(thread_init_handlers));
}

static void *pthread_entry(void *data)
{
	int ret;

	ret = runtime_init_thread();
	BUG_ON(ret);

	kthread_attach();
	sched_start();

	/* never reached unless things are broken */
	BUG();
	return NULL;
}

/**
 * runtime_init - starts the runtime
 * @cfgpath: the path to the configuration file
 * @main_fn: the first function to run as a thread
 * @arg: an argument to @main_fn
 *
 * Does not return if successful, otherwise return  < 0 if an error.
 */
int runtime_init(const char *cfgpath, thread_fn_t main_fn, void *arg)
{
	pthread_t tid[NCPU];
	int ret, i;

	ret = base_init();
	if (ret) {
		log_err("base library global init failed, ret = %d", ret);
		return ret;
	}

	ret = cfg_load(cfgpath);
	if (ret)
		return ret;

	ret = ioqueues_init(maxks);
	if (ret) {
		log_err("couldn't initialize ioqueues, ret = %d", ret);
		return ret;
	}

	ret = run_init_handlers("global", global_init_handlers,
			ARRAY_SIZE(global_init_handlers));
	if (ret)
		return ret;

	log_info("spawning %d kthreads", maxks);
	for (i = 1; i < maxks; i++) {
		ret = pthread_create(&tid[i], NULL, pthread_entry, NULL);
		BUG_ON(ret);
	}

	ret = runtime_init_thread();
	BUG_ON(ret);

	ret = ioqueues_register_iokernel();
	if (ret) {
		log_err("couldn't register with iokernel, ret = %d", ret);
		return ret;
	}

	/* point of no return starts here */

	ret = thread_spawn_main(main_fn, arg);
	BUG_ON(ret);

	kthread_attach();

	ret = run_init_handlers("late", late_init_handlers,
			ARRAY_SIZE(late_init_handlers));
	BUG_ON(ret);

	sched_start();

	/* never reached unless things are broken */
	BUG();
	return 0;
}
