/*
 * time.h - timekeeping utilities
 */

#pragma once

#include <base/types.h>
#include <asm/ops.h>

#define ONE_SECOND	1000000
#define ONE_MS		1000
#define ONE_US		1

extern int cycles_per_us;
extern uint64_t start_tsc; 

/**
 * microtime - gets the number of microseconds since the process started
 * This routine is very inexpensive, even compared to clock_gettime().
 */
static inline uint64_t microtime(void)
{
	return (rdtsc() - start_tsc) / cycles_per_us;
}

extern void __time_delay_us(uint64_t us);

/**
 * delay_us - pauses the CPU for microseconds
 * @us: the number of microseconds
 */
static inline void delay_us(uint64_t us)
{
	__time_delay_us(us);
}

/**
 * delay_ms - pauses the CPU for milliseconds
 * @ms: the number of milliseconds
 */
static inline void delay_ms(uint64_t ms)
{
	/* TODO: yield instead of spin */
	__time_delay_us(ms * ONE_MS);
}
