/*
 * test_ping.c - sends ping echo requests
 */

#include <unistd.h>
#include <stdio.h>

#include <base/log.h>
#include <base/time.h>
#include <net/ping.h>
#include <runtime/thread.h>

#define N_PINGS 10
#define DEST_IP_ADDR 3232235778 // 192.168.1.2

static void main_handler(void *arg)
{
	int i, ret;
	uint64_t next_ping_time;

	ret = net_ping_init();
	if (ret) {
		log_err("failed to init ping");
		return;
	}

	next_ping_time = microtime();
	for (i = 0; i < N_PINGS; i++) {
		net_send_ping(i, DEST_IP_ADDR);

		/* wait 1 second before sending next ping */
		next_ping_time += 1000 * 1000;
		while (microtime() < next_ping_time)
			thread_yield();
	}
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
