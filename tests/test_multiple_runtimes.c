/*
 * test_multiple_runtimes.c - tests initialization of multiple runtimes
 */

#include <unistd.h>

#include <base/log.h>
#include <runtime/thread.h>

#define N_RUNTIMES	8
#define SLEEP_S		5

static void main_handler(void *arg)
{
	sleep(SLEEP_S);
}

int main(int argc, char *argv[])
{
	int i, pid, ret;

	for (i = 0; i < N_RUNTIMES; i++) {
		pid = fork();
		BUG_ON(pid == -1);

		if (pid == 0) {
			ret = runtime_init(main_handler, NULL, 1);
			BUG_ON(ret < 0);
		}

		sleep(1);
	}

	return 0;
}
