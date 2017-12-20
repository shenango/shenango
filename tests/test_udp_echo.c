/*
 * test_runtime_thread.c - tests basic thread spawning
 */

#include <base/stddef.h>
#include <base/log.h>
#include <base/time.h>
#include <runtime/thread.h>
#include <runtime/sync.h>
#include <runtime/net/usocket.h>

#define N		1000000
#define NCORES		4

static struct addr laddr = {
		.ip = 0,
		.port = 5000
};


struct mbuf *net_tx_alloc_mbuf(void);

static void responder(int descriptor, struct mbuf *m, struct addr raddr)
{
	struct mbuf *r = net_tx_alloc_mbuf();

	void *ptr = mbuf_put(r, mbuf_length(m));
	memcpy(ptr, mbuf_data(m), mbuf_length(m));

	usocket_send_zc(descriptor, r, raddr);

	mbuf_free(m);

}

static void main_handler(void *arg)
{

	int fd;

	fd = usocket_create();
	BUG_ON(fd < 0);

	usocket_bind_handler(fd, laddr, &responder);

	while (1) thread_yield();


}

int main(int argc, char *argv[])
{
	int ret;

	ret = runtime_init(main_handler, NULL, NCORES);
	if (ret) {
		log_err("failed to start runtime");
		return ret;
	}

	return 0;
}
