/*
 * netperf.c - a UDP client similar to netperf
 */

#include <stdio.h>
#include <string.h>
#include <limits.h>

#include <base/stddef.h>
#include <base/log.h>
#include <base/time.h>
#include <net/ip.h>
#include <runtime/thread.h>
#include <runtime/sync.h>
#include <runtime/udp.h>

#define NETPERF_PORT	8000

/* experiment parameters */
static struct netaddr raddr;
static int nworkers;
static int seconds;
static uint64_t stop_us;
static size_t payload_len;
static int depth;

struct client_rr_args {
	waitgroup_t *wg;
	uint64_t reqs;
};

static void client_worker(void *arg)
{
	unsigned char buf[UDP_MAX_PAYLOAD];
	struct client_rr_args *args = (struct client_rr_args *)arg;
	udpconn_t *c;
	struct netaddr laddr;
	ssize_t ret;
	int budget = depth;

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
		while (budget) {
			ret = udp_write(c, buf, payload_len);
			if (ret != payload_len) {
				log_err("udp_write() failed, ret = %ld", ret);
				break;
			}
			budget--;
		}

		ret = udp_read(c, buf, UDP_MAX_PAYLOAD);
		if (ret != payload_len) {
			log_err("udp_read() failed, ret = %ld", ret);
			break;
		}

		budget++;
		args->reqs++;
	}

	udp_close(c);
done:
	waitgroup_done(args->wg);
}

static void do_client(void *arg)
{
	waitgroup_t wg;
	struct client_rr_args *arg_tbl;
	int i, ret;
	uint64_t reqs = 0;

	log_info("client-mode UDP: %d workers, %ld bytes, %d seconds %d depth",
		 nworkers, payload_len, seconds, depth);

	arg_tbl = calloc(nworkers, sizeof(*arg_tbl));
	BUG_ON(!arg_tbl);

	waitgroup_init(&wg);
	waitgroup_add(&wg, nworkers);
	stop_us = microtime() + seconds * ONE_SECOND;
	for (i = 0; i < nworkers; i++) {
		arg_tbl[i].wg = &wg;
		arg_tbl[i].reqs = 0;
		ret = thread_spawn(client_worker, &arg_tbl[i]);
		BUG_ON(ret);
	}

	waitgroup_wait(&wg);

	for (i = 0; i < nworkers; i++)
		reqs += arg_tbl[i].reqs;

	log_info("measured %f reqs/s", (double)reqs / seconds);
}

static void server_recv_one(struct udp_spawn_data *d)
{
	/* try to echo the packet back */
	udp_send(d->buf, d->len, d->laddr, d->raddr);
	udp_spawn_data_release(d->release_data);
}

static void do_server(void *arg)
{
	waitgroup_t wg;
	struct netaddr laddr;
	udpspawner_t *s;
	int ret;

	laddr.ip = 0;
	laddr.port = NETPERF_PORT;

	ret = udp_create_spawner(laddr, server_recv_one, &s);
	BUG_ON(ret);

	/* wait forever */
	waitgroup_init(&wg);
	waitgroup_add(&wg, 1);
	waitgroup_wait(&wg);
}

static int str_to_ip(const char *str, uint32_t *addr)
{
	uint8_t a, b, c, d;
	if(sscanf(str, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) != 4) {
		return -EINVAL;
	}

	*addr = MAKE_IP_ADDR(a, b, c, d);
	return 0;
}

static int str_to_long(const char *str, long *val)
{
	char *endptr;

	*val = strtol(str, &endptr, 10);
	if (endptr == str || (*endptr != '\0' && *endptr != '\n') ||
	    ((*val == LONG_MIN || *val == LONG_MAX) && errno == ERANGE))
		return -EINVAL;
	return 0;
}

int main(int argc, char *argv[])
{
	int ret;
	long tmp;
	uint32_t addr;
	thread_fn_t fn;

	if (argc < 8) {
		printf("%s: [config_file_path] [mode] [nworkers] [ip] [time] "
		       "[payload_len] [depth]\n", argv[0]);
		return -EINVAL;
	}

	if (!strcmp(argv[2], "UDP_CLIENT")) {
		fn = do_client;
	} else if (!strcmp(argv[2], "UDP_SERVER")) {
		fn = do_server;
	} else {
		printf("invalid mode '%s'\n", argv[2]);
		return -EINVAL;
	}

	ret = str_to_long(argv[3], &tmp);
	if (ret) {
		printf("couldn't parse [nworkers] '%s'\n", argv[3]);
		return -EINVAL;
	}
	nworkers = tmp;

	ret = str_to_ip(argv[4], &addr);
	if (ret) {
		printf("couldn't parse [ip] '%s'\n", argv[4]);
		return -EINVAL;
	}
	raddr.ip = addr;
	raddr.port = NETPERF_PORT;

	ret = str_to_long(argv[5], &tmp);
	if (ret) {
		printf("couldn't parse [time] '%s'\n", argv[5]);
		return -EINVAL;
	}
	seconds = tmp;

	ret = str_to_long(argv[6], &tmp);
	if (ret) {
		printf("couldn't parse [payload_len] '%s'\n", argv[6]);
		return -EINVAL;
	}
	payload_len = tmp;

	ret = str_to_long(argv[7], &tmp);
	if (ret) {
		printf("couldn't parse [depth] '%s'\n", argv[7]);
		return -EINVAL;
	}
	depth = tmp;

	ret = runtime_init(argv[1], fn, NULL);
	if (ret) {
		printf("failed to start runtime\n");
		return ret;
	}

	return 0;
}
