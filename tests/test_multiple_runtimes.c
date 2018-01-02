/*
 * test_multiple_runtimes.c - tests initialization of multiple runtimes
 */

#include <stdio.h>
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

	if (argc < 2) {
		printf("arg must be config file\n");
		return -EINVAL;
	}

	for (i = 0; i < N_RUNTIMES; i++) {
		pid = fork();
		BUG_ON(pid == -1);

		if (pid == 0) {
			ret = runtime_init(argv[1], main_handler, NULL);
			BUG_ON(ret < 0);
		}

		sleep(1);
	}

	return 0;
}
