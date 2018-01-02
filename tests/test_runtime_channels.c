#include <stdio.h>

#include <base/stddef.h>
#include <base/log.h>
#include <base/time.h>
#include <runtime/chan.h>
#include <runtime/thread.h>
#include <runtime/sync.h>

#define NCORES		4
#define N		1000000

struct test_args {
	chan_t *chan;
	waitgroup_t *wg;
	int count;
};

static void ping_pong_thread(void *arg)
{
	struct test_args *tg = arg;
	int ball, prev = 0, ret;

	while (1) {
		ret = chan_recv(tg->chan, &ball, 1);
		BUG_ON(ret);
		BUG_ON(prev && ball != prev + 1);
		if (ball++ == tg->count)
			break;
		ret = chan_send(tg->chan, &ball, 1);
		BUG_ON(ret);
		if (ball == tg->count)
			break;
		prev = ball;
	}

	BUG_ON(!ball || !prev);

	waitgroup_done(tg->wg);
}

static void test_ping_pong(void)
{
	waitgroup_t wg;
	chan_t chan;
	int ball = 0, ret;

	ret = chan_create(&chan, sizeof(int), 0);
	BUG_ON(ret);
	waitgroup_init(&wg);
	waitgroup_add(&wg, 2);

	struct test_args ta = {
		.chan = &chan,
		.wg = &wg,
		.count = 4000,
	};

	ret = thread_spawn(ping_pong_thread, &ta);
	BUG_ON(ret);

	ret = chan_send(&chan, &ball, 1);
	BUG_ON(ret);

	ret = thread_spawn(ping_pong_thread, &ta);
	BUG_ON(ret);

	waitgroup_wait(&wg);
	chan_close(&chan);

	log_info("Ping pong test completed");
}

static void send_thread(void *arg)
{
	struct test_args *tg = arg;
	int i, ret;

	for (i = 0; i < tg->count; i++) {
		ret = chan_send(tg->chan, &tg->count, 1);
		BUG_ON(ret);
	}

	log_info("Send thread sent %d messages", tg->count);

	if (tg->wg)
		waitgroup_done(tg->wg);
}

static void receive_thread_n(void *arg)
{
	struct test_args *tg = arg;
	int i, j, ret;

	for (i = 0; i < tg->count; i++) {
		ret = chan_recv(tg->chan, &j, 1);
		BUG_ON(ret);
	}

	log_info("Receive thread received %d messages", tg->count);

	if (tg->wg)
		waitgroup_done(tg->wg);
}

static void receive_thread(void *arg)
{
	struct test_args *tg = arg;
	int i;

	while (chan_recv(tg->chan, &i, 1) != -EIO)
		tg->count++;

	log_info("Receive thread received %d messages", tg->count);

	if (tg->wg)
		waitgroup_done(tg->wg);
}

static void *test_multi_send_recv(void)
{
	waitgroup_t wait_send, wait_recv;
	chan_t chan;
	int i, count, ret;
	struct test_args receiver_info[NCORES];

	ret = chan_create(&chan, sizeof(int), 10);
	BUG_ON(ret);

	waitgroup_init(&wait_send);
	waitgroup_init(&wait_recv);
	waitgroup_add(&wait_send, NCORES);
	waitgroup_add(&wait_recv, NCORES);

	struct test_args sender_info = {
		.chan = &chan,
		.wg = &wait_send,
		.count = 40000,
	};

	for (i = 0; i < NCORES; i++) {
		ret = thread_spawn(send_thread, &sender_info);
		BUG_ON(ret);
	}

	for (i = 0; i < NCORES; i++) {
		receiver_info[i].chan = &chan;
		receiver_info[i].wg = &wait_recv;
		receiver_info[i].count = 0;
		ret = thread_spawn(receive_thread, &receiver_info[i]);
		BUG_ON(ret);
	}

	waitgroup_wait(&wait_send);
	chan_close(&chan);
	waitgroup_wait(&wait_recv);

	count = 0;
	for (i = 0; i < NCORES; i++)
		count += receiver_info[i].count;
	BUG_ON(count != NCORES * 40000);

	log_info("Multiple sender + receiver test passed");

	return NULL;
}


static void *test_multi_send(void)
{
	waitgroup_t wg;
	chan_t chan;
	int i, ret;

	ret = chan_create(&chan, sizeof(int), 10);
	BUG_ON(ret);

	waitgroup_init(&wg);
	waitgroup_add(&wg, NCORES);

	struct test_args tgs = {
		.chan = &chan,
		.wg = &wg,
		.count = 40000,
	};

	for (i = 0; i < NCORES; i++) {
		ret = thread_spawn(send_thread, &tgs);
		BUG_ON(ret);
	}

	struct test_args stg = {
		.chan = &chan,
		.wg = NULL,
		.count = 40000 * NCORES,
	};

	receive_thread_n(&stg);
	waitgroup_wait(&(wg));
	chan_close(&chan);

	log_info("Multiple sender test passed");

	return NULL;

}

static void *test_multi_recv(void)
{
	waitgroup_t wg;
	chan_t chan;
	int i, ret;
	struct test_args tgs[NCORES];

	ret = chan_create(&chan, sizeof(int), 10);
	BUG_ON(ret);

	waitgroup_init(&wg);
	waitgroup_add(&wg, NCORES);

	for (i = 0; i < NCORES; i++) {
		tgs[i].chan = &chan;
		tgs[i].wg = &wg;
		tgs[i].count = 0;
		ret = thread_spawn(receive_thread, &tgs[i]);
		BUG_ON(ret);
	}

	struct test_args stg = {
		.chan = &chan,
		.wg = NULL,
		.count = 100000,
	};

	send_thread(&stg);
	chan_close(&chan);
	waitgroup_wait(&(wg));

	for (i = 0; i < NCORES; i++)
		stg.count -= tgs[i].count;

	BUG_ON(stg.count != 0);

	log_info("Multiple receiver test passed");

	return NULL;

}

static void *test_basic(void)
{
	int i, rcv, ret;
	chan_t chan;

	ret = chan_create(&chan, sizeof(int), 100);
	BUG_ON(ret);

	for (i = 0; i < 100; i++) {
		ret = chan_send(&chan, &i, 0);
		BUG_ON(ret);
	}

	ret = chan_send(&chan, &i, 0);
	BUG_ON(ret != -EAGAIN);

	for (i = 0; i < 100; i++) {
		ret = chan_recv(&chan, &rcv, 0);
		BUG_ON(ret || rcv != i);
	}

	ret = chan_recv(&chan, &rcv, 0);
	BUG_ON(ret != -EAGAIN);

	chan_close(&chan);

	ret = chan_recv(&chan, &rcv, 0);
	BUG_ON(ret != -EIO);

	ret = chan_create(&chan, sizeof(int), 0);
	BUG_ON(ret);

	ret = chan_recv(&chan, &rcv, 0);
	BUG_ON(ret != -EAGAIN);

	ret = chan_send(&chan, &rcv, 0);
	BUG_ON(ret != -EAGAIN);

	chan_close(&chan);

	log_info("Passed single threaded channel test");

	return NULL;
}

static void main_handler(void *arg)
{
	test_basic();
	test_ping_pong();
	test_multi_send();
	test_multi_recv();
	test_multi_send_recv();
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc < 2) {
		printf("arg must be config file\n");
		return -EINVAL;
	}

	ret = runtime_init(argv[1], main_handler, NULL);
	if (ret) {
		printf("failed to start runtime\n");
		return ret;
	}

	return 0;
}
