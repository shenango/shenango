#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sched.h>
#include <linux/futex.h>
#include <sys/time.h>
#include <errno.h>
#include <stdlib.h>

#include <deque>
#include <random>
#include <algorithm>
#include <atomic>

typedef uint64_t cycle_t;

static inline cycle_t rdtsc(void)
{
	uint32_t a, d;
	asm volatile("rdtsc" : "=a" (a), "=d" (d));
	return ((uint64_t)a) | (((uint64_t)d) << 32);
}

static inline cycle_t rdtscp(uint32_t *auxp)
{
	uint32_t a, d, c;
	asm volatile("rdtscp" : "=a" (a), "=d" (d), "=c" (c));
	if (auxp)
		*auxp = c;
	return ((uint64_t)a) | (((uint64_t)d) << 32);
}

#define N	1000
static cycle_t results[N];
static int nr;

int main(int argc, char *argv[])
{
	cycle_t start, end;

	while (nr < N) {
		start = rdtsc();
		end = rdtscp(NULL);
		if (end - start > 1000)
			results[nr++] = end - start;
	}

        std::sort(std::begin(results), std::end(results));
        printf("median: %ld 99th: %ld 99.9th: %ld 99.99th: %ld\n",
               results[nr / 2], results[nr * 99 / 100],
               results[nr * 999 / 1000], results[nr * 9999 / 10000]);
	return 0;
}
