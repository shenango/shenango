/*
 * test_ping.c - sends ping echo requests
 */

#include <unistd.h>

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

	ret = runtime_init(main_handler, NULL, 1);
	if (ret) {
		log_err("failed to start runtime");
		return ret;
	}

	return 0;
}
