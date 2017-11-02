/*
 * control.h - the control interface for the I/O kernel
 */

#pragma once

#include <base/bitmap.h>
#include <base/limits.h>
#include <iokernel/shm.h>

/* The abstract namespace path for the control socket. */
#define CONTROL_SOCK_PATH	"\0/control/iokernel.sock"

enum {
	QUEUE_TYPE_RX = 0,
	QUEUE_TYPE_TX_PACKET,
	QUEUE_TYPE_TX_COMPLETION,
};

struct queue_spec {
	DEFINE_BITMAP(core_mask, NCPU);
	unsigned int	type;
	unsigned int	msg_count;
	shmptr_t	msg_buf;
	shmptr_t	wb;
};

enum {
	SCHED_PRIORITY_SYSTEM = 0, /* high priority, system-level services */
	SCHED_PRIORITY_NORMAL,     /* normal priority, typical tasks */
	SCHED_PRIORITY_BATCH,      /* low priority, batch processing */
};

struct control_status {
	DEFINE_BITMAP(active_core_mask, NCPU);
} __aligned(CACHE_LINE_SIZE);

struct control_sched_config {
	unsigned int	sched_priority;
	unsigned int	sched_max_cores;
	unsigned int	sched_congestion_latency_us;
	unsigned int	sched_scaleout_latency_us;
};

struct control_hdr {
	struct control_sched_config sched;
	struct control_status status;
	unsigned int	queue_count;
	unsigned int	pad;
	struct queue_spec queues[];
};
