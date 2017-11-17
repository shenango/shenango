/*
 * control.c - the control-plane for the I/O kernel
 */

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#include <base/stddef.h>
#include <base/mem.h>
#include <base/log.h>
#include <iokernel/control.h>

#include "defs.h"

#define CONTROL_MAX_PROC	1024

static int controlfd;
static int clientfds[CONTROL_MAX_PROC];
static struct proc *clients[CONTROL_MAX_PROC];
static int nr_clients;

static int control_init_lrpc_in(struct shm_region *r, struct queue_spec *s,
				struct lrpc_chan_in *c)
{
	struct lrpc_msg *tbl;
	uint32_t *wb;

	if (!is_power_of_two(s->msg_count))
		return -EINVAL;

	tbl = (struct lrpc_msg *)shmptr_to_ptr(r, s->msg_buf,
		sizeof(struct lrpc_msg) * s->msg_count);
	if (!tbl)
		return -EINVAL;

	wb = (uint32_t *)shmptr_to_ptr(r, s->wb, sizeof(*wb));
	if (!wb)
		return -EINVAL;

	lrpc_init_in(c, tbl, s->msg_count, wb);
	return 0;
}

static int control_init_lrpc_out(struct shm_region *r, struct queue_spec *s,
				 struct lrpc_chan_out *c)
{
	struct lrpc_msg *tbl;
	uint32_t *wb;

	if (!is_power_of_two(s->msg_count))
		return -EINVAL;

	tbl = (struct lrpc_msg *)shmptr_to_ptr(r, s->msg_buf,
		sizeof(struct lrpc_msg) * s->msg_count);
	if (!tbl)
		return -EINVAL;

	wb = (uint32_t *)shmptr_to_ptr(r, s->wb, sizeof(*wb));
	if (!wb)
		return -EINVAL;

	lrpc_init_out(c, tbl, s->msg_count, wb);
	return 0;

}

static struct proc *control_create_proc(mem_key_t key, size_t len, pid_t pid)
{
	struct control_hdr hdr;
	struct shm_region reg;
	struct proc *p;
	void *shbuf;
	int i, ret;

	/* attach the shared memory region */
	if (len < sizeof(hdr))
		goto fail;
	shbuf = mem_map_shm(key, NULL, len, PGSIZE_2MB, false);
	if (shbuf == MAP_FAILED)
		goto fail;

	/* parse the control header */
	memcpy(&hdr, (struct control_hdr *)shbuf, sizeof(hdr)); /* TOCTOU */
	if (hdr.magic != CONTROL_HDR_MAGIC)
		goto fail_unmap;
	if (hdr.thread_count > NCPU || hdr.thread_count == 0)
		goto fail_unmap;

	/* create the process */
	p = malloc(sizeof(*p));
	if (!p)
		goto fail_unmap;

	p->thread_count = hdr.thread_count;
	p->sched_cfg = hdr.sched_cfg;
	reg.base = shbuf;
	reg.len = len;
	p->region = reg;
	if (eth_addr_is_multicast(&hdr.mac) || eth_addr_is_zero(&hdr.mac))
		goto fail_free_proc;
	p->mac = hdr.mac;

	/* initialize the threads */
	for (i = 0; i < hdr.thread_count; i++) {
		struct thread *th = &p->threads[i];
		struct thread_spec *s = &hdr.threads[i];

		/* attach the RX queue */
		ret = control_init_lrpc_out(&reg, &s->rxq, &th->rxq);
		if (ret)
			goto fail_free_proc;

		/* attach the TX packet queue */
		ret = control_init_lrpc_in(&reg, &s->txpktq, &th->txpktq);
		if (ret)
			goto fail_free_proc;

		/* attach the TX command queue */
		ret = control_init_lrpc_in(&reg, &s->txcmdq, &th->txcmdq);
		if (ret)
			goto fail_free_proc;
	}

	return p;

fail_free_proc:
	free(p);
fail_unmap:
	mem_unmap_shm(shbuf);
fail:
	log_err("control: couldn't attach pid %d", pid);
	return NULL;
}

static void control_destroy_proc(struct proc *p)
{
	mem_unmap_shm(p->region.base);
	free(p);
}

static void control_add_client(void)
{
	struct proc *p;
	struct ucred ucred;
	socklen_t len;
	mem_key_t shm_key;
	size_t shm_len;
	ssize_t ret;
	int fd;

	fd = accept(controlfd, NULL, NULL);
	if (fd == -1) {
		log_err("control: accept() failed [%s]", strerror(errno));
		return;
	}

	if (nr_clients >= CONTROL_MAX_PROC) {
		log_err("control: hit client process limit");
		goto fail;
	}

	len = sizeof(struct ucred);
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len) == -1) {
		log_err("control: getsockopt() failed [%s]", strerror(errno));
		goto fail;
	}

	ret = read(fd, &shm_key, sizeof(shm_key));
	if (ret != sizeof(shm_key)) {
		log_err("control: read() failed, len=%ld [%s]",
			ret, strerror(errno));
		goto fail;
	}

	ret = read(fd, &shm_len, sizeof(shm_len));
	if (ret != sizeof(shm_len)) {
		log_err("control: read() failed, len=%ld [%s]",
			ret, strerror(errno));
		goto fail;
	}

	p = control_create_proc(shm_key, shm_len, ucred.pid);
	if (!p) {
		log_err("control: failed to create process '%d'", ucred.pid);
		goto fail;
	}

	clients[nr_clients] = p;
	clientfds[nr_clients++] = fd;
	return;

fail:
	close(fd);
}

static void control_remove_client(int fd)
{
	int i;

	for (i = 0; i < nr_clients; i++) {
		if (clientfds[i] == fd)
			break;
	}

	if (i == nr_clients) {
		WARN();
		return;
	}

	control_destroy_proc(clients[i]);
	clients[i] = clients[nr_clients - 1];
	clientfds[i] = clientfds[nr_clients - 1];
	nr_clients--;
	close(fd);
}

static void control_loop(void)
{
	fd_set readset;
	int maxfd, i, nrdy;

	while (1) {
		maxfd = controlfd;
		FD_ZERO(&readset);
		FD_SET(controlfd, &readset);

		for (i = 0; i < nr_clients; i++) {
			FD_SET(clientfds[i], &readset);
			maxfd = (clientfds[i] > maxfd) ? clientfds[i] : maxfd;
		}

		nrdy = select(maxfd + 1, &readset, NULL, NULL, NULL);
		if (nrdy == -1) {
			log_err("control: select() failed [%s]",
				strerror(errno));
			BUG();
		}

		for (i = 0; i <= maxfd && nrdy > 0; i++) {
			if (!FD_ISSET(i, &readset))
				continue;

			if (i == controlfd) {
				/* accept a new conection */
				control_add_client();
			} else {
				/* close an existing connection */
				control_remove_client(i);
			}

			nrdy--;
		}
	}
}

static void *control_thread(void *data)
{
	control_loop();
	return NULL;
}

int control_init(void)
{
	struct sockaddr_un addr;
	pthread_t tid;
	int sfd;

	BUILD_ASSERT(strlen(CONTROL_SOCK_PATH) <= sizeof(addr.sun_path) - 1);

	memset(&addr, 0x0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, CONTROL_SOCK_PATH, sizeof(addr.sun_path) - 1);
 
	sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sfd == -1) {
		log_err("control: socket() failed [%s]", strerror(errno));
		return -errno;
	}
 
	if (bind(sfd, (struct sockaddr *)&addr,
		 sizeof(struct sockaddr_un)) == -1) {
		log_err("control: bind() failed [%s]", strerror(errno));
		close(sfd);
		return -errno;
	}

	if (listen(sfd, 100) == -1) {
		log_err("control: listen() failed[%s]", strerror(errno));
		close(sfd);
		return -errno;
	}

	log_info("control: spawning control thread");
	controlfd = sfd;
	if (pthread_create(&tid, NULL, control_thread, NULL) == -1) {
		log_err("control: pthread_create() failed [%s]",
			strerror(errno));
		close(sfd);
		return -errno;
	}

	return 0;	
}
