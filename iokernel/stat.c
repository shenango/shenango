
#include <stdio.h>

#include <base/log.h>

#include "defs.h"

#define BUFSIZE 4096

uint64_t stats[NR_STATS];

static const char *stat_names[] = {
	"RX_UNREGISTERED_MAC",
	"RX_UNICAST_FAIL",
	"RX_BROADCAST_FAIL",
	"RX_UNHANDLED",
	"RX_JOIN_FAIL",
	"TX_COMPLETION_OVERFLOW",
	"TX_COMPLETION_FAIL",
	"RX_PULLED",
	"COMMANDS_PULLED",
	"COMPLETION_DRAINED",
	"COMPLETION_ENQUEUED",
	"BATCH_TOTAL",
	"TX_PULLED",
	"TX_BACKPRESSURE",
	"RQ_GRANT",
	"RX_GRANT",
	"ADJUSTS",
};

BUILD_ASSERT(ARRAY_SIZE(stat_names) == NR_STATS);

void print_stats(void)
{
	int i;
	char buf[BUFSIZE + 1];
	size_t done = 0;

	static uint64_t last_stats[NR_STATS];

	for (i = 0; i < NR_STATS; i++) {
		done += snprintf(buf + done, BUFSIZE - done, "%s: %lu\n", stat_names[i], stats[i] - last_stats[i]);
		last_stats[i] = stats[i];
	}

	buf[done] = 0;

	fprintf(stderr, "Stats:\n%s", buf);
}
