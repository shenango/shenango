/*
 * test_runtime_rcu.c - tests RCU
 */

#include <stdlib.h>
#include <stdio.h>

#include <base/stddef.h>
#include <base/log.h>
#include <base/time.h>
#include <runtime/thread.h>
#include <runtime/sync.h>
#include <runtime/rcu.h>

#define N		1000000
#define NCORES		4
#define FIRST_VAL	0x1000000
#define SECOND_VAL	0x2000000

static waitgroup_t release_wg;

struct test_obj {
	int		foo;
	struct rcu_head	rcu;
};

static __rcu struct test_obj *test_ptr;

static void test_release(struct rcu_head *head)
{
	struct test_obj *o = container_of(head, struct test_obj, rcu);
	free(o);
	waitgroup_done(&release_wg);
}

static void read_handler(void *arg)
{
	bool ptr_swapped = false;
	struct test_obj *o;
	int i;

	for (i = 0; i < N; i++) {
		rcu_read_lock();
		o = rcu_dereference(test_ptr);
		if (o->foo == SECOND_VAL)
			ptr_swapped = true;
		BUG_ON(o->foo != (ptr_swapped ? SECOND_VAL : FIRST_VAL));
		rcu_read_unlock();
		thread_yield();
	}
	waitgroup_t *wg_parent = (waitgroup_t *)arg;
	waitgroup_done(wg_parent);
}

static void main_handler(void *arg)
{
	struct test_obj *o, *o2;
	waitgroup_t wg;
	int i, ret;

	log_info("started main_handler() thread");
	waitgroup_init(&release_wg);
	waitgroup_add(&release_wg, 1);
	o = malloc(sizeof(*o));
	BUG_ON(!o);
	o->foo = FIRST_VAL;
	RCU_INIT_POINTER(test_ptr, o);

	log_info("creating threads to read RCU object.");

	waitgroup_init(&wg);
	waitgroup_add(&wg, NCORES);
	for (i = 0; i < NCORES; i++) {
		ret = thread_spawn(read_handler, &wg);
		BUG_ON(ret);
	}

	thread_yield();
	o2 = malloc(sizeof(*o));
	o2->foo = SECOND_VAL;
	rcu_assign_pointer(test_ptr, o2);
	rcu_free(&o->rcu, test_release);

	waitgroup_wait(&wg);
	log_info("readers finished.");
	waitgroup_wait(&release_wg);
	log_info("RCU release finished.");
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
