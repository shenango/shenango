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

static struct proc *control_create_proc(mem_key_t key, pid_t pid)
{

}

static void control_destory_proc(struct proc *p)
{

}

static void control_add_client(void)
{
	struct proc *p;
	struct ucred ucred;
	socklen_t len;
	mem_key_t key;
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

	ret = read(fd, &key, sizeof(key));
	if (ret != sizeof(key)) {
		log_err("control: read() failed, len=%ld [%s]",
			ret, strerror(errno));
		goto fail;
	}

	p = control_create_proc(key, ucred.pid);
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

static void control_remove_client(void)
{

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
			init_shutdown(EXIT_FAILURE);
		}

		for (i = 0; i <= maxfd && nrdy > 0; i++) {
			if (!FD_ISSET(i, &readset))
				continue;

			if (i == controlfd) {
				/* accept a new conection */
				control_add_client();
			} else {
				/* close an existing connection */
				control_remove_client();
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
