/*
 * stat.c - support for statistics and counters
 */

#include <string.h>
#include <stdio.h>

#include <base/stddef.h>
#include <base/log.h>
#include <runtime/thread.h>
#include <runtime/udp.h>

#include "defs.h"

/* port 40 is permanently reserved, so should be fine for now */
#define STAT_PORT	40

static const char *stat_names[] = {
	/* scheduler counters */
	"reschedules",
	"sched_cycles",
	"program_cycles",
	"threads_stolen",
	"nets_stolen",
	"timers_stolen",
	"nets_local",
	"timers_local",

	/* network stack counters */
	"rx_bytes",
	"rx_packets",
	"tx_bytes",
	"tx_packets",
	"drops",
};

/* must correspond exactly to STAT_* enum definitions in defs.h */
BUILD_ASSERT(ARRAY_SIZE(stat_names) == STAT_NR);

static ssize_t stat_write_buf(char *buf, size_t len)
{
	uint64_t stats[STAT_NR];
	char *pos = buf, *end = buf + len;
	int i, j, ret;

	memset(stats, 0, sizeof(stats));

	/* gather stats from each kthread */
	/* FIXME: not correct when parked kthreads removed from @ks */
	for (i = 0; i < nrks; i++) {
		for (j = 0; j < STAT_NR; j++)
			stats[j] += ks[i]->stats[j];
	}

	/* write out the stats to the buffer */
	for (j = 0; j < STAT_NR; j++) {
		ret = snprintf(buf, end - pos, "%s:%ld,",
			       stat_names[j], stats[j]);
		if (ret < 0) {
			return -EINVAL;
		} else if (ret >= end - pos) {
			return -E2BIG;
		}

		pos += ret;
	}

	return pos - buf + 1;
}

static void stat_worker(void *arg)
{
	const size_t cmd_len = strlen("stat");
	char buf[UDP_MAX_PAYLOAD];
	struct udpaddr laddr, raddr;
	udpconn_t *c;
	ssize_t ret;

	laddr.ip = 0;
	laddr.port = STAT_PORT;

	ret = udp_listen(laddr, &c);
	if (ret) {
		log_err("stat: udp_listen failed, ret = %ld", ret);
		return;
	}

	while (true) {
		ret = udp_read_from(c, buf, UDP_MAX_PAYLOAD, &raddr);
		if (ret < cmd_len)
			continue;
		if (strncmp(buf, "stat", cmd_len) != 0)
			continue;

		ret = stat_write_buf(buf, UDP_MAX_PAYLOAD);
		if (ret < 0) {
			log_err("stat: couldn't generate stat buffer");
			continue;
		}
		assert(ret <= UDP_MAX_PAYLOAD);

		udp_write_to(c, buf, ret, &raddr);
	}
}

/**
 * stat_init_late - starts the stat responder thread
 *
 * Returns 0 if succesful.
 */
int stat_init_late(void)
{
	return thread_spawn(stat_worker, NULL);
}
