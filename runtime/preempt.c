/*
 * preempt.c - support for kthread preemption
 */

#include "runtime/preempt.h"

#include "defs.h"

/* the current preemption count */
__thread unsigned int preempt_cnt = PREEMPT_NOT_PENDING;

/* handles preemption */
void __preempt(void)
{
	kthread_park(true);
}
