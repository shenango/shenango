/*
 * ioqueues.c
 */

#include <fcntl.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <base/log.h>
#include <base/lrpc.h>
#include <base/mem.h>

#include <net/ethernet.h>
#include <net/mbuf.h>

#include "defs.h"

#define PACKET_QUEUE_MCOUNT 8192
#define COMMAND_QUEUE_MCOUNT 16

struct iokernel_control iok;

static int generate_random_mac(struct eth_addr *mac)
{
	int fd, ret;
	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return -1;

	ret = read(fd, mac, sizeof(*mac));
	close(fd);
	if (ret != sizeof(*mac))
		return -1;

	mac->addr[0] &= ~ETH_ADDR_GROUP;
	mac->addr[0] |= ETH_ADDR_LOCAL_ADMIN;

	return 0;
}

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

	ret = align_up(ret, PGSIZE_2MB);

	// Egress mbufs
	q = ETH_MAX_LEN + sizeof(struct mbuf);
	ret += q * PACKET_QUEUE_MCOUNT;
	ret = align_up(ret, PGSIZE_2MB);

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

static int control_setup(unsigned int threads)
{
	struct control_hdr *hdr;
	struct shm_region *r = &iok.r, *ingress_region = &iok.ingress_region;
	char *ptr;
	int i, ret;
	size_t shm_len;

	ret = generate_random_mac(&iok.mac);
	if (ret < 0)
		return ret;

	shm_len = calculate_shm_space(threads);

	BUILD_ASSERT(sizeof(iok.mac) >= sizeof(mem_key_t));
	iok.key = *(mem_key_t*)(&iok.mac);

	r->len = shm_len;
	r->base = mem_map_shm(iok.key, NULL, shm_len, PGSIZE_2MB, true);
	if (r->base == MAP_FAILED) {
		log_err("control_setup: mem_map_shm() failed");
		return -1;
	}

	ingress_region->base =
	    mem_map_shm(INGRESS_MBUF_SHM_KEY, NULL, INGRESS_MBUF_SHM_SIZE,
			PGSIZE_2MB, false);
	if (ingress_region->base == MAP_FAILED) {
		log_err("control_setup: failed to map ingress region");
		mem_unmap_shm(r->base);
		return -1;
	}

	hdr = r->base;
	hdr->magic = CONTROL_HDR_MAGIC;
	hdr->thread_count = threads;
	hdr->mac = iok.mac;

	hdr->sched_cfg.priority = SCHED_PRIORITY_NORMAL;
	hdr->sched_cfg.max_cores = threads;
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
	mem_unmap_shm(iok.ingress_region.base);
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

static int setup_egress_mbufs(void)
{

	int ret;
	void *buf;
	size_t buf_size;

	buf_size = (ETH_MAX_LEN + sizeof(struct mbuf)) * PACKET_QUEUE_MCOUNT;
	buf_size = align_up(buf_size, PGSIZE_2MB);

	buf = shmptr_to_ptr(&iok.r, align_up(iok.next_free, PGSIZE_2MB), buf_size);
	if (buf == NULL)
		return -ENOMEM;

	ret = mbuf_tcache_allocator_init(buf, buf_size, PACKET_QUEUE_MCOUNT,
				   ETH_MAX_LEN, 0);
	if (ret)
		return ret;

	buf += buf_size;
	iok.next_free = ptr_to_shmptr(&iok.r, buf, 0);

	return 0;

}

int ioqueues_init_thread(void)
{
	int ret;

	// TODO: Attach queues?

	ret = mbuf_tcache_allocator_init_thread();
	if (ret) {
		log_err("ioqueues_init_thread: failed to setup tcache mbufs, "
			"ret = %d",
			ret);
		return ret;
	}

	return 0;
}

int ioqueues_init(unsigned int threads)
{
	int ret;

	ret = control_setup(threads);
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

	ret = setup_egress_mbufs();
	if (ret) {
		log_err("ioqueues_init: setup_egress_mbufs() failed, ret = %d", ret);
		close(iok.fd);
		control_cleanup();
		return ret;
	}

	return 0;
}
