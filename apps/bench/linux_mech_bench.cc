extern "C" {
#include <signal.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <base/compiler.h>
#include <base/lrpc.h>
#include <base/mem.h>
#include <iokernel/shm.h>
}

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <vector>

namespace {

using sec = std::chrono::duration<double, std::micro>;

constexpr int N = (10 * 1000 * 1000);
int MSG_COUNT = 1024;

struct thread_data {
	int read_efd;
	int write_efd;
};

struct shm_thread_data {
	struct shm_region r;
	struct queue_spec q_in;
	struct queue_spec q_out;
};

static pid_t gettid(void)
{
	#ifdef SYS_gettid
	pid_t tid = syscall(SYS_gettid);
	#else
	#error "SYS_gettid unavailable on this system"
	#endif

	return tid;
}

void Report(std::vector<double> timings)
{
	// Report statistics.
	std::sort(timings.begin(), timings.end());
	double sum = std::accumulate(timings.begin(), timings.end(), 0.0);
	double mean = sum / timings.size();
	double count = static_cast<double>(timings.size());
	double median = timings[count * 0.5];
	double p9 = timings[count * 0.9];
	double p99 = timings[count * 0.99];
	double p999 = timings[count * 0.999];
	double p9999 = timings[count * 0.9999];
	double min = timings[0];
	double max = timings[timings.size() - 1];
	std::cout << std::setprecision(3) << std::fixed
			<< "n: "		<< timings.size()
			<< " min: "		<< min
			<< " mean: "	<< mean
			<< " median: "	<< median
			<< " 90%: "		<< p9
			<< " 99%: "		<< p99
			<< " 99.9%: "	<< p999
			<< " 99.99%: "	<< p9999
			<< " max: "		<< max << std::endl;
}

/*
 * Repeatedly block on reading an eventfd.
 */
void *BlockOnEventfd(void *data)
{
	struct thread_data *my_t = (struct thread_data *) data;
	uint64_t val;
	int ret;

	std::cout << "in child thread, tid: " << gettid() << std::endl;
	while (true) {
		ret = read(my_t->read_efd, &val, sizeof(val));
		if (ret != sizeof(uint64_t))
			std::cerr << "error reading eventfd" << std::endl;
		if (val > 1)
			std::cout << "read value > 1: " << val << std::endl;
	}

	return NULL;
}

/*
 * Busy spin, incrementing a counter
 */
void *BusySpin(void *data)
{
	int counter = 0;

	std::cout << "in child thread, tid: " << gettid() << std::endl;
	while (true) {
		counter++;
		barrier();
	}

	return NULL;
}

/*
 * Benchmark the latency of calling setaffinity to move a thread to a different
 * core.
 */
void RunAffinityBench()
{
	pid_t child_pid, child_tid;
	int ret;
	struct thread_data t;
	pthread_t pthread_tid;
	cpu_set_t cpuset_0;
	cpu_set_t cpuset_1;
	std::vector<double> timings;

	std::cout << "running affinity bench" << std::endl;

	/* initialize efd */
	t.read_efd = eventfd(0, 0);
	if (t.read_efd == -1)
		std::cerr << "error creating eventfd" << std::endl;

	child_pid = fork();
	if (child_pid == 0) {
		/* in child */
		ret = pthread_create(&pthread_tid, NULL, BlockOnEventfd, &t);
		if (ret) {
			std::cerr << "failed to create pthread" << std::endl;
			exit(0);
		}
		while (true);
	} else {
		/* in parent, wait for child thread to be spawned */
		sleep(1);

		CPU_ZERO(&cpuset_0);
		CPU_SET(2, &cpuset_0);
		CPU_ZERO(&cpuset_1);
		CPU_SET(4, &cpuset_1);

		/* guess that child thread will have a pid of child proc's pid + 1 */
		child_tid = child_pid + 1;
		std::cout << "in parent, guessing child tid: " << child_tid
				<< std::endl;
		for (int i = 0; i < N; i++) {
			barrier();
			auto start = std::chrono::steady_clock::now();
			barrier();

			/* bounce the child to a different core. */
			if (i % 2 == 0)
				ret = sched_setaffinity(child_tid, sizeof(cpu_set_t),
						&cpuset_0);
			else
				ret = sched_setaffinity(child_tid, sizeof(cpu_set_t),
						&cpuset_1);

			if (ret) {
				std::cerr << "failed to setaffinity" << std::endl;
				exit(0);
			}

			barrier();
			auto finish = std::chrono::steady_clock::now();
			barrier();

			timings.push_back(
					std::chrono::duration_cast < sec
							> (finish - start).count());
		}
	}
	kill(child_pid, SIGKILL);

	Report(timings);
}

/*
 * Benchmark the latency of writing to an eventfd when another thread is
 * blocked on it.
 */
void RunEventfdCallerBench()
{
	pid_t child_pid;
	struct thread_data t;
	int ret;
	pthread_t pthread_tid;
	std::vector<double> timings;
	uint64_t val = 1;

	std::cout << "running eventfd caller bench" << std::endl;

	/* initialize efd */
	t.read_efd = eventfd(0, 0);
	if (t.read_efd == -1)
		std::cerr << "error creating eventfd" << std::endl;

	child_pid = fork();
	if (child_pid == 0) {
		/* in child */
		ret = pthread_create(&pthread_tid, NULL, BlockOnEventfd, &t);
		if (ret) {
			std::cerr << "failed to create pthread" << std::endl;
			exit(0);
		}
		while (true);
	} else {
		/* in parent, wait for child thread to be spawned */
		sleep(1);

		std::cout << "in parent" << std::endl;
		for (int i = 0; i < N; i++) {
			barrier();
			auto start = std::chrono::steady_clock::now();
			barrier();

			/* write to the efd */
			ret = write(t.read_efd, &val, sizeof(val));
			if (ret != sizeof(val))
				std::cout << "error writing to eventfd" << std::endl;

			barrier();
			auto finish = std::chrono::steady_clock::now();
			barrier();

			timings.push_back(
					std::chrono::duration_cast < sec
							> (finish - start).count());

			/* sleep briefly, to ensure the reader is blocked again */
			usleep(1);
		}
	}
	kill(child_pid, SIGKILL);

	Report(timings);
}

/*
 * Repeatedly read from one efd and write to another.
 */
void *EventfdReadWrite(void *data)
{
	struct thread_data *my_t = (struct thread_data *) data;
	uint64_t val;
	int ret;

	std::cout << "in child thread, tid: " << gettid() << std::endl;
	while (true) {
		ret = read(my_t->read_efd, &val, sizeof(val));
		if (ret != sizeof(uint64_t) || val > 1)
			std::cerr << "error reading eventfd" << std::endl;
		ret = write(my_t->write_efd, &val, sizeof(val));
		if (ret != sizeof(uint64_t))
			std::cerr << "error writing eventfd" << std::endl;
	}

	return NULL;
}

/*
 * Benchmark the latency of communicating with a thread using a pair of
 * eventfds.
 */
void RunEventfdCommunicationBench()
{
	pid_t child_pid;
	struct thread_data t;
	int ret;
	pthread_t pthread_tid;
	std::vector<double> timings;
	uint64_t val = 1;

	std::cout << "running eventfd communication bench" << std::endl;

	/* initialize efd */
	t.read_efd = eventfd(0, 0);
	if (t.read_efd == -1)
		std::cerr << "error creating eventfd" << std::endl;
	t.write_efd = eventfd(0, 0);
	if (t.write_efd == -1)
		std::cerr << "error creating eventfd" << std::endl;

	child_pid = fork();
	if (child_pid == 0) {
		/* in child */
		ret = pthread_create(&pthread_tid, NULL, EventfdReadWrite, &t);
		if (ret) {
			std::cerr << "failed to create pthread" << std::endl;
			exit(0);
		}
		while (true);
	} else {
		/* in parent, wait for child thread to be spawned */
		sleep(1);

		std::cout << "in parent" << std::endl;
		for (int i = 0; i < N; i++) {
			barrier();
			auto start = std::chrono::steady_clock::now();
			barrier();

			/* write to the first efd */
			ret = write(t.read_efd, &val, sizeof(val));
			if (ret != sizeof(val))
				std::cout << "error writing to eventfd" << std::endl;

			/* read from the second efd */
			ret = read(t.write_efd, &val, sizeof(val));
			if (ret != sizeof(val) || val > 1)
				std::cout << "error reading from eventfd" << std::endl;

			barrier();
			auto finish = std::chrono::steady_clock::now();
			barrier();

			timings.push_back(
					std::chrono::duration_cast < sec
							> (finish - start).count());
		}
	}
	kill(child_pid, SIGKILL);

	Report(timings);
}

static void empty_sig_handler(int signo)
{
	/* do nothing */
	return;
}

/*
 * Benchmark the latency of sending a signal to a thread in another process.
 */
void RunSignalCallerBench()
{
	pid_t child_pid, child_tid;
	int ret;
	pthread_t pthread_tid;
	std::vector<double> timings;

	std::cout << "running signal caller bench" << std::endl;

	child_pid = fork();
	if (child_pid == 0) {
		/* in child */

		/* register signal handler */
		signal(SIGUSR1, empty_sig_handler);

		ret = pthread_create(&pthread_tid, NULL, BusySpin, NULL);
		if (ret) {
			std::cerr << "failed to create pthread" << std::endl;
			exit(0);
		}
		while (true);
	} else {
		/* in parent, wait for child thread to be spawned */
		sleep(1);

		/* guess that child thread will have a pid of child proc's pid + 1 */
		child_tid = child_pid + 1;
		std::cout << "in parent, guessing child tid: " << child_tid
				<< std::endl;
		for (int i = 0; i < N; i++) {
			barrier();
			auto start = std::chrono::steady_clock::now();
			barrier();

			/* send a signal to the child */
			syscall(SYS_tgkill, child_pid, child_tid, SIGUSR1);

			barrier();
			auto finish = std::chrono::steady_clock::now();
			barrier();

			timings.push_back(
					std::chrono::duration_cast < sec
							> (finish - start).count());
		}
	}
	kill(child_pid, SIGKILL);

	Report(timings);
}

pid_t parent_pid;
bool received_signal;
auto signal_finish = std::chrono::steady_clock::now();

/*
 * Signal handler that sends a signal to another thread.
 */
static void sig_sig_handler(int signo)
{
	/* send a signal to the parent */
	syscall(SYS_tgkill, parent_pid, parent_pid, SIGUSR1);
	return;
}

/*
 * Signal handler that records the signal receipt time.
 */
static void time_sig_handler(int signo)
{
	barrier();
	signal_finish = std::chrono::steady_clock::now();
	received_signal = true;
	barrier();

	return;
}

/*
 * Benchmark the latency of signaling back and forth between two processes.
 */
void RunSignalCommunicationBench()
{
	pid_t child_pid, child_tid;
	int ret;
	pthread_t pthread_tid;
	std::vector<double> timings;

	std::cout << "running signal communication bench" << std::endl;

	parent_pid = getpid();

	child_pid = fork();
	if (child_pid == 0) {
		/* in child */

		/* register signal handler */
		signal(SIGUSR1, sig_sig_handler);

		ret = pthread_create(&pthread_tid, NULL, BusySpin, NULL);
		if (ret) {
			std::cerr << "failed to create pthread" << std::endl;
			exit(0);
		}
		while (true);
	} else {
		/* in parent, wait for child thread to be spawned */
		sleep(1);

		/* register signal handler */
		signal(SIGUSR1, time_sig_handler);

		/* guess that child thread will have a pid of child proc's pid + 1 */
		child_tid = child_pid + 1;
		std::cout << "in parent, guessing child tid: " << child_tid
				<< std::endl;
		for (int i = 0; i < N; i++) {
			received_signal = false;
			barrier();
			auto start = std::chrono::steady_clock::now();
			barrier();

			/* send a signal to the child */
			syscall(SYS_tgkill, child_pid, child_tid, SIGUSR1);

			/* wait to get a signal back from the child */
			usleep(10 * 1000);
			if (!received_signal)
				std::cerr << "parent did not receive signal" << std::endl;

			timings.push_back(
					std::chrono::duration_cast < sec
							> (signal_finish - start).count());
		}
	}
	kill(child_pid, SIGKILL);

	Report(timings);
}

/*
 * Repeatedly dequeue from shared memory queue.
 */
void *DequeueFromLRPC(void *data)
{
	struct shm_thread_data *my_t = (struct shm_thread_data *) data;
	struct lrpc_chan_in c;
	int ret;
	uint64_t cmd;
	unsigned long payload;

	/* init queue */
	ret = shm_init_lrpc_in(&my_t->r, &my_t->q_in, &c);
	if (ret)
		std::cerr << "failed to init shared memory queue" << std::endl;

	std::cout << "in child thread, tid: " << gettid() << std::endl;
	while (true)
		lrpc_recv(&c, &cmd, &payload);

	return NULL;
}

/*
 * Benchmark the latency of writing to an eventfd when another thread is
 * blocked on it.
 */
void RunLRPCCallerBench()
{
	pid_t child_pid;
	struct shm_thread_data t;
	char *ptr;
	struct lrpc_chan_out c;
	int ret;
	pthread_t pthread_tid;
	std::vector<double> timings;

	std::cout << "running LRPC caller bench" << std::endl;

	/* init shared memory */
	t.r.len = align_up(sizeof(struct lrpc_msg) * MSG_COUNT, CACHE_LINE_SIZE) +
			align_up(sizeof(uint32_t), CACHE_LINE_SIZE);
	t.r.len = align_up(t.r.len, PGSIZE_2MB);
	t.r.base = mem_map_shm(rand(), NULL, t.r.len, PGSIZE_2MB, true);
	if (t.r.base == MAP_FAILED) {
		std::cerr << "failed to create shared memory" << std::endl;
		exit(0);
	}

	/* init queue in shared memory */
	ptr = (char *) t.r.base;
	t.q_in.msg_buf = ptr_to_shmptr(&t.r, ptr, sizeof(struct lrpc_msg) * MSG_COUNT);
	ptr += align_up(sizeof(struct lrpc_msg) * MSG_COUNT, CACHE_LINE_SIZE);
	t.q_in.wb = ptr_to_shmptr(&t.r, ptr, sizeof(uint32_t));
	t.q_in.msg_count = MSG_COUNT;
	ret = shm_init_lrpc_out(&t.r, &t.q_in, &c);
	if (ret) {
		std::cerr << "failed to init lrpc queue" << std::endl;
		exit(0);
	}

	child_pid = fork();
	if (child_pid == 0) {
		/* in child */
		ret = pthread_create(&pthread_tid, NULL, DequeueFromLRPC, &t);
		if (ret) {
			std::cerr << "failed to create pthread" << std::endl;
			exit(0);
		}
		while (true);
	} else {
		/* in parent, wait for child thread to be spawned */
		sleep(1);

		std::cout << "in parent" << std::endl;
		for (int i = 0; i < N; i++) {
			barrier();
			auto start = std::chrono::steady_clock::now();
			barrier();

			/* write to the lrpc queue */
			if (!lrpc_send(&c, 1, 2))
				std::cerr << "error sending lrpc " << i << std::endl;

			barrier();
			auto finish = std::chrono::steady_clock::now();
			barrier();

			timings.push_back(
					std::chrono::duration_cast < sec
							> (finish - start).count());
		}
	}
	kill(child_pid, SIGKILL);

	Report(timings);
}

/*
 * Repeatedly dequeue from a shared memory queue and then enqueue to another.
 */
void *LRPCDequeueEnqueue(void *data)
{
	struct shm_thread_data *my_t = (struct shm_thread_data *) data;
	struct lrpc_chan_in c_in;
	struct lrpc_chan_out c_out;
	int ret;
	uint64_t cmd;
	unsigned long payload;

	/* init queues */
	ret = shm_init_lrpc_in(&my_t->r, &my_t->q_in, &c_in);
	if (ret)
		std::cerr << "failed to init shared memory queue" << std::endl;
	ret = shm_init_lrpc_out(&my_t->r, &my_t->q_out, &c_out);
	if (ret)
		std::cerr << "failed to init shared memory queue" << std::endl;

	std::cout << "in child thread, tid: " << gettid() << std::endl;
	while (true) {
		while (!lrpc_recv(&c_in, &cmd, &payload)) {
			/* try again */
		}

		if (!lrpc_send(&c_out, 3, 4))
			std::cerr << "child error sending lrpc" << std::endl;
	}

	return NULL;
}

/*
 * Benchmark the latency of communciating between two threads using a pair of
 * LRPC queues.
 */
void RunLRPCCommunicationBench()
{
	pid_t child_pid;
	struct shm_thread_data t;
	char *ptr;
	struct lrpc_chan_out c_out;
	struct lrpc_chan_in c_in;
	int ret;
	pthread_t pthread_tid;
	uint64_t cmd;
	unsigned long payload;
	std::vector<double> timings;

	std::cout << "running LRPC communication bench" << std::endl;

	/* init shared memory */
	t.r.len = 2 * (align_up(sizeof(struct lrpc_msg) * MSG_COUNT, CACHE_LINE_SIZE) +
			align_up(sizeof(uint32_t), CACHE_LINE_SIZE));
	t.r.len = align_up(t.r.len, PGSIZE_2MB);
	t.r.base = mem_map_shm(rand(), NULL, t.r.len, PGSIZE_2MB, true);
	if (t.r.base == MAP_FAILED) {
		std::cerr << "failed to create shared memory" << std::endl;
		exit(0);
	}

	/* init queues in shared memory */
	ptr = (char *) t.r.base;
	t.q_in.msg_buf = ptr_to_shmptr(&t.r, ptr, sizeof(struct lrpc_msg) * MSG_COUNT);
	ptr += align_up(sizeof(struct lrpc_msg) * MSG_COUNT, CACHE_LINE_SIZE);
	t.q_in.wb = ptr_to_shmptr(&t.r, ptr, sizeof(uint32_t));
	ptr += align_up(sizeof(uint32_t), CACHE_LINE_SIZE);
	t.q_in.msg_count = MSG_COUNT;
	ret = shm_init_lrpc_out(&t.r, &t.q_in, &c_out);
	if (ret) {
		std::cerr << "failed to init lrpc queue" << std::endl;
		exit(0);
	}
	t.q_out.msg_buf = ptr_to_shmptr(&t.r, ptr, sizeof(struct lrpc_msg) * MSG_COUNT);
	ptr += align_up(sizeof(struct lrpc_msg) * MSG_COUNT, CACHE_LINE_SIZE);
	t.q_out.wb = ptr_to_shmptr(&t.r, ptr, sizeof(uint32_t));
	ptr += align_up(sizeof(uint32_t), CACHE_LINE_SIZE);
	t.q_out.msg_count = MSG_COUNT;
	ret = shm_init_lrpc_in(&t.r, &t.q_out, &c_in);
	if (ret) {
		std::cerr << "failed to init lrpc queue" << std::endl;
		exit(0);
	}

	child_pid = fork();
	if (child_pid == 0) {
		/* in child */
		ret = pthread_create(&pthread_tid, NULL, LRPCDequeueEnqueue, &t);
		if (ret) {
			std::cerr << "failed to create pthread" << std::endl;
			exit(0);
		}
		while (true);
	} else {
		/* in parent, wait for child thread to be spawned */
		sleep(1);

		std::cout << "in parent" << std::endl;
		for (int i = 0; i < N; i++) {
			barrier();
			auto start = std::chrono::steady_clock::now();
			barrier();

			/* write to the lrpc queue */
			if (!lrpc_send(&c_out, 1, 2))
				std::cerr << "error sending lrpc " << i << std::endl;

			/* read from the other lrpc queue */
			while (!lrpc_recv(&c_in, &cmd, &payload)) {
				/* try again */
			}

			barrier();
			auto finish = std::chrono::steady_clock::now();
			barrier();

			timings.push_back(
					std::chrono::duration_cast < sec
							> (finish - start).count());
		}
	}
	kill(child_pid, SIGKILL);

	Report(timings);
}

} // anonymous namespace

int main(int argc, char *argv[])
{
	int ret;
	cpu_set_t base_cpuset;

	if (argc < 2) {
		std::cerr << "usage: [cmd] ..." << std::endl;
		return -EINVAL;
	}

	/* pin self to a set of non-hyperthread pair cores on the same socket */
	CPU_ZERO(&base_cpuset);
	CPU_SET(2, &base_cpuset);
	CPU_SET(4, &base_cpuset);
	CPU_SET(6, &base_cpuset);
	CPU_SET(8, &base_cpuset);

	ret = sched_setaffinity(getpid(), sizeof(cpu_set_t), &base_cpuset);
	if (ret) {
		std::cerr << "failed to setaffinity" << std::endl;
		exit(0);
	}

	std::string cmd = argv[1];
	if (cmd.compare("set_affinity") == 0) {
		RunAffinityBench();
	} else if (cmd.compare("eventfd_caller") == 0) {
		RunEventfdCallerBench();
	} else if (cmd.compare("eventfd_communication") == 0) {
		RunEventfdCommunicationBench();
	} else if (cmd.compare("signal_caller") == 0) {
		RunSignalCallerBench();
	} else if (cmd.compare("signal_communication") == 0) {
		RunSignalCommunicationBench();
	} else if (cmd.compare("lrpc_caller") == 0) {
		RunLRPCCallerBench();
	} else if (cmd.compare("lrpc_communication") == 0) {
		RunLRPCCommunicationBench();
	} else if (cmd.compare("all") == 0) {
		RunAffinityBench();
		RunEventfdCallerBench();
		RunEventfdCommunicationBench();
		RunSignalCallerBench();
		RunSignalCommunicationBench();
		RunLRPCCallerBench();
		RunLRPCCommunicationBench();
	} else {
		std::cerr << "invalid command: " << cmd << std::endl;
		return -EINVAL;
	}

	return 0;
}
