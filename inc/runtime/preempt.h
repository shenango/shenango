/*
 * preempt.h - support for kthread preemption
 */

#pragma once

#include <base/stddef.h>

extern void __preempt(void);
extern __thread unsigned int preempt_cnt;

#define PREEMPT_NOT_PENDING	(1 << 31)

extern void __preempt(void);

/**
 * preempt_disable - disables preemption
 *
 * Can be nested.
 */
static inline void preempt_disable(void)
{
	preempt_cnt++;
	barrier();
}

/**
 * preempt_enable - reenables preemption
 *
 * Can be nested.
 */
static inline void preempt_enable(void)
{
	barrier();
	if (unlikely(--preempt_cnt == 0))
		__preempt();
}

/**
 * preempt_enable - reenables preemption without checking for conditions
 *
 * Can be nested.
 */
static inline void preempt_enable_nocheck(void)
{
	barrier();
	preempt_cnt--;
}

/**
 * preempt_needed - returns true if a preemption event is stuck waiting
 */
static inline bool preempt_needed(void)
{
	return (preempt_cnt & PREEMPT_NOT_PENDING) == 0;
}

/**
 * assert_preempt_disabled - asserts that preemption is disabled
 */
static inline void assert_preempt_disabled(void)
{
	assert((preempt_cnt & ~PREEMPT_NOT_PENDING) > 0);
}
