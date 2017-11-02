/*
 * init.c - initializes the runtime
 */

#include <pthread.h>

#include <base/init.h>
#include <base/log.h>
#include <base/limits.h>
#include <runtime/thread.h>

#include "defs.h"

static int runtime_init_thread(void)
{
	int ret;

	ret = base_init_thread();
	if (ret) {
		log_err("base_init_thread() failed, ret = %d", ret);
		return ret;
	}

	ret = stack_init_thread();
	if (ret) {
		log_err("stack_init_thread() failed, ret = %d", ret);
		return ret;
	}

	ret = sched_init_thread();
	if (ret) {
		log_err("sched_init_thread() failed, ret = %d", ret);
		return ret;
	}

	return 0;
}

static void *pthread_entry(void *data)
{
	int ret;

	ret = runtime_init_thread();
	BUG_ON(ret);

	sched_start();

	/* never reached unless things are broken */
	BUG();
	return NULL;
}

/**
 * runtime_init - starts the runtime
 * @main_fn: the first function to run as a thread
 * @arg: an argument to @main_fn
 * @cores: the number of cores to use
 *
 * Does not return if successful, otherwise return  < 0 if an error.
 */
int runtime_init(thread_fn_t main_fn, void *arg, unsigned int cores)
{
	pthread_t tid[NCPU];
	int ret, i;

	if (cores < 1)
		return -EINVAL;

	ret = base_init();
	if (ret) {
		log_err("base_init() failed, ret = %d", ret);
		return ret;
	}

	ret = stack_init();
	if (ret) {
		log_err("stack_init() failed, ret = %d", ret);
		return ret;
	}

	ret = sched_init();
	if (ret) {
		log_err("sched_init() failed, ret = %d", ret);
		return ret;
	}

	/* point of no return starts here */

	for (i = 1; i < cores; i++) {
		ret = pthread_create(&tid[i], NULL, pthread_entry, NULL);
		BUG_ON(ret);
	}

	ret = runtime_init_thread();
	BUG_ON(ret);

	ret = thread_spawn_main(main_fn, arg);
	BUG_ON(ret);

	sched_start();

	/* never reached unless things are broken */
	BUG();
	return 0;
}
