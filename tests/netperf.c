/*
 * netperf.c - a UDP client similar to netperf
 */

#include <stdio.h>
#include <string.h>

#include <base/stddef.h>
#include <base/log.h>
#include <base/time.h>
#include <runtime/thread.h>
#include <runtime/sync.h>
#include <runtime/udp.h>

#define NETPERF_PORT	8000

/* experiment parameters */
static struct udpaddr raddr;
static int nworkers;
static int seconds;
static uint64_t stop_us;
static size_t payload_len;

struct client_rr_args {
	waitgroup_t *wg;
	uint64_t reqs;
};

static void client_rr_worker(void *arg)
{
	unsigned char buf[UDP_MAX_PAYLOAD];
	struct client_rr_args *args = (struct client_rr_args *)arg;
	udpconn_t *c;
	struct udpaddr laddr;
	ssize_t ret;

	/* local IP + ephemeral port */
	laddr.ip = 0;
	laddr.port = 0;

	memset(buf, 0xAB, payload_len);

	ret = udp_dial(laddr, raddr, &c);
	if (ret) {
		log_err("udp_dial() failed, ret = %ld", ret);
		goto done;
	}

	while (microtime() < stop_us) {
		ret = udp_write(c, buf, payload_len);
		if (ret) {
			log_err("udp_write() failed, ret = %ld", ret);
			break;
		}

		ret = udp_read(c, buf, payload_len);
		if (ret) {
			log_err("udp_read() failed, ret = %ld", ret);
			break;
		}

		args->reqs++;
	}

	udp_close(c);
done:
	waitgroup_done(args->wg);
}

static void do_client_rr(void *arg)
{
	waitgroup_t wg;
	struct client_rr_args *arg_tbl;
	int i, ret;
	uint64_t reqs = 0;

	log_info("client-mode UDP_RR: %d workers, %ld bytes, %d seconds",
		 nworkers, payload_len, seconds);

	arg_tbl = calloc(nworkers, sizeof(*arg_tbl));
	BUG_ON(!arg_tbl);

	waitgroup_init(&wg);
	waitgroup_add(&wg, nworkers);
	stop_us = microtime() + seconds * ONE_SECOND;
	for (i = 0; i < nworkers; i++) {
		arg_tbl[i].wg = &wg;
		arg_tbl[i].reqs = 0;
		ret = thread_spawn(client_rr_worker, &arg_tbl[i]);
		BUG_ON(ret);
	}

	waitgroup_wait(&wg);

	for (i = 0; i < nworkers; i++)
		reqs += arg_tbl[i].reqs;

	log_info("measured %f reqs/s", (double)reqs / seconds);
}

static void do_server_rr(void *arg)
{

}

int main(int argc, char *argv[])
{
	int ret;

	if (argc < 5) {
		printf("%s: [config_file_path] [mode] [nworkers] [ip] [time] "
		       "[payload_len]\n", argv[0]);
		return -EINVAL;
	}

	ret = runtime_init(argv[1], do_client_rr, NULL);
	if (ret) {
		printf("failed to start runtime\n");
		return ret;
	}

	return 0;
}
