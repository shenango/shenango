/*
 * ioqueues.c
 */

#include <string.h>
#include <sys/ipc.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <base/log.h>
#include <base/lrpc.h>
#include <base/mem.h>

#include "defs.h"

#define PACKET_QUEUE_MCOUNT 8192
#define COMMAND_QUEUE_MCOUNT 16

struct iokernel_control iok;

// Could be a macro really, this is totally static :/
static size_t calculate_shm_space(unsigned int thread_count)
{

	size_t ret = 0, q;

	// Header + queue_spec information
	ret += sizeof(struct control_hdr);
	ret += sizeof(struct thread_spec) * thread_count;
	ret = align_up(ret, CACHE_LINE_SIZE);

	// Packet Queues
	q = sizeof(struct lrpc_msg) * PACKET_QUEUE_MCOUNT;
	q = align_up(q, CACHE_LINE_SIZE);
	q += align_up(sizeof(uint32_t), CACHE_LINE_SIZE);
	ret += 2 * q * thread_count;

	q = sizeof(struct lrpc_msg) * COMMAND_QUEUE_MCOUNT;
	q = align_up(q, CACHE_LINE_SIZE);
	q += align_up(sizeof(uint32_t), CACHE_LINE_SIZE);
	ret += q * thread_count;

	ret += 0; // TODO: Calculate space for the actual packets!

	return ret;
}

static void ioqueue_alloc(struct shm_region *r, struct queue_spec *q,
			  char **ptr, size_t msg_count)
{
	q->msg_buf = ptr_to_shmptr(r, *ptr, sizeof(struct lrpc_msg) * msg_count);
	*ptr += align_up(sizeof(struct lrpc_msg) * msg_count, CACHE_LINE_SIZE);

	q->wb = ptr_to_shmptr(r, *ptr, sizeof(uint32_t));
	*ptr += align_up(sizeof(uint32_t), CACHE_LINE_SIZE);

	q->msg_count = msg_count;
}

static int control_setup(void)
{
	struct control_hdr *hdr;
	struct shm_region *r = &iok.r;
	char *ptr;
	int i;
	size_t shm_len;

	shm_len = calculate_shm_space(NCPU);

	// TODO: fixme (argv[0]?)
	iok.key = ftok(__FILE__, getpid());
	if (iok.key == -1) {
		log_err("control_setup: ftok() failed [%s]", strerror(errno));
		return -errno;
	}

	r->len = shm_len;
	r->base = mem_map_shm(iok.key, NULL, shm_len, PGSIZE_2MB, true);
	if (r->base == MAP_FAILED) {
		log_err("control_setup: mem_map_shm() failed");
		return -1;
	}

	hdr = r->base;
	hdr->magic = CONTROL_HDR_MAGIC;
	hdr->thread_count = NCPU;

	// TODO: fixme
	struct eth_addr t1 = {.addr = {0, 0, 0, 0, 0, 1},};
	hdr->mac = t1;
	hdr->sched_cfg.priority = SCHED_PRIORITY_NORMAL;
	hdr->sched_cfg.max_cores = NCPU;
	hdr->sched_cfg.congestion_latency_us = 0;
	hdr->sched_cfg.scaleout_latency_us = 0;

	ptr = r->base;
	ptr += sizeof(*hdr) + sizeof(struct thread_spec) * hdr->thread_count;
	ptr = (char *)align_up((uintptr_t)ptr, CACHE_LINE_SIZE);

	for (i = 0; i < hdr->thread_count; i++) {
		struct thread_spec *tspec = &iok.threads[i];
		ioqueue_alloc(r, &tspec->rxq, &ptr, PACKET_QUEUE_MCOUNT);
		ioqueue_alloc(r, &tspec->txpktq, &ptr, PACKET_QUEUE_MCOUNT);
		ioqueue_alloc(r, &tspec->txcmdq, &ptr, COMMAND_QUEUE_MCOUNT);
	}

	memcpy(hdr->threads, iok.threads,
	       sizeof(struct thread_spec) * hdr->thread_count);

	iok.next_free = ptr_to_shmptr(r, ptr, 0);

	return 0;
}

static void control_cleanup(void)
{
	mem_unmap_shm(iok.r.base);
}


static int register_iokernel(void)
{

	int ret;

	struct sockaddr_un addr;
	BUILD_ASSERT(strlen(CONTROL_SOCK_PATH) <= sizeof(addr.sun_path) - 1);
	memset(&addr, 0x0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, CONTROL_SOCK_PATH, sizeof(addr.sun_path) - 1);

	iok.fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (iok.fd == -1) {
		log_err("register_iokernel: socket() failed [%s]", strerror(errno));
		return -errno;
	}

	if (connect(iok.fd, (struct sockaddr *)&addr,
		 sizeof(struct sockaddr_un)) == -1) {
		log_err("register_iokernel: connect() failed [%s]", strerror(errno));
		goto fail;
	}

	ret = write(iok.fd, &iok.key, sizeof(iok.key));
	if (ret != sizeof(iok.key)) {
		log_err("register_iokernel: write() failed [%s]", strerror(errno));
		goto fail;
	}

	ret = write(iok.fd, &iok.r.len, sizeof(iok.r.len));
	if (ret != sizeof(iok.r.len)) {
		log_err("register_iokernel: write() failed [%s]", strerror(errno));
		goto fail;
	}

	return 0;

fail:
	close(iok.fd);
	return -errno;

}

int ioqueues_init(void)
{
	int ret;

	ret = control_setup();
	if (ret) {
		log_err("ioqueues_init: control_setup() failed, ret = %d", ret);
		return ret;
	}

	ret = register_iokernel();
	if (ret) {
		log_err("ioqueues_init: register_iokernel() failed, ret = %d", ret);
		control_cleanup();
		return ret;
	}

	return 0;
}
