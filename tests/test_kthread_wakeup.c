/*
 * test_kthread_wakeup.c - tests waking of kthreads
 */

#include <stdio.h>

#include <base/stddef.h>
#include <base/log.h>
#include <base/time.h>
#include <runtime/thread.h>
#include <runtime/sync.h>

#define NTHREADS	10

atomic_t n_threads_run;

static void work_handler(void *arg)
{
	waitgroup_t *wg_parent = (waitgroup_t *)arg;

	atomic_inc(&n_threads_run);
	waitgroup_done(wg_parent);
}

static void main_handler(void *arg)
{
	waitgroup_t wg;
	int i, ret;

	log_info("started main_handler() thread");

	/* wait until all initialization threads have finished so that the
	   runqueue is empty */
	for (i = 0; i < 5; i++) {
		thread_yield();
		delay_ms(1000);
	}

	/* test that new kthreads are woken up to handle threads spawned by a
	   long-running thread */
	atomic_write(&n_threads_run, 0);
	waitgroup_init(&wg);
	waitgroup_add(&wg, NTHREADS);
	for (i = 0; i < NTHREADS; i++) {
		ret = thread_spawn(work_handler, &wg);
		BUG_ON(ret);
	}
	delay_ms(10 * 1000);

	BUG_ON(atomic_read(&n_threads_run) == 0);
	waitgroup_wait(&wg);
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc < 2) {
		printf("arg must be config file\n");
		return -EINVAL;
	}

	ret = runtime_init(argv[1], main_handler, NULL);
	if (ret) {
		printf("failed to start runtime\n");
		return ret;
	}

	return 0;
}
