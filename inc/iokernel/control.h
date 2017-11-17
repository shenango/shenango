/*
 * control.h - the control interface for the I/O kernel
 */

#pragma once

#include <base/limits.h>
#include <iokernel/shm.h>

/* The abstract namespace path for the control socket. */
#define CONTROL_SOCK_PATH	"\0/control/iokernel.sock"

/* describes a shared memory queue */
struct queue_spec {
	size_t			msg_count;
	shmptr_t		msg_buf;
	shmptr_t		wb;
};

/* describes a runtime kernel thread */
struct thread_spec {
	struct queue_spec 	rxq;
	struct queue_spec 	txpktq;
	struct queue_spec 	txcmdq;
};

enum {
	SCHED_PRIORITY_SYSTEM = 0, /* high priority, system-level services */
	SCHED_PRIORITY_NORMAL,     /* normal priority, typical tasks */
	SCHED_PRIORITY_BATCH,      /* low priority, batch processing */
};

/* describes scheduler options */
struct sched_spec {
	unsigned int		priority;
	unsigned int		max_cores;
	unsigned int		congestion_latency_us;
	unsigned int		scaleout_latency_us;
};

#define CONTROL_HDR_MAGIC	0x696f6b3a /* "iok:" */

/* the main control header */
struct control_hdr {
	unsigned int		magic;
	unsigned int		thread_count;
	struct sched_spec	sched_cfg;
	struct thread_spec	threads[];
};
