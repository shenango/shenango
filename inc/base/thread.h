/*
 * thread.h - perthread data and other utilities
 */

#pragma once

#include <base/stddef.h>
#include <base/limits.h>
#include <base/cpu.h>

/* used to define perthread variables */
#define DEFINE_PERTHREAD(type, name) \
	typeof(type) __perthread_##name __perthread \
	__attribute__((section(".perthread,\"\",@nobits#")))

/* used to make perthread variables externally available */
#define DECLARE_PERTHREAD(type, name) \
	extern DEFINE_PERTHREAD(type, name)

extern void *perthread_offsets[NCPU];
extern __thread void *perthread_ptr;

/**
 * perthread_get_remote - get a perthread variable on a specific thread
 * @var: the perthread variable
 * @cpu: the cpu core number
 *
 * Returns a perthread variable.
 */
#define perthread_get_remote(var, cpu)				\
	(*((__force typeof(__perthread_##var) *)		\
	 ((uintptr_t)&__perthread_##var + (uintptr_t)perthread_offsets[cpu])))

static inline void *__perthread_get(void __perthread *key)
{
	return (__force void *)((uintptr_t)key + (uintptr_t)perthread_ptr);
}

/**
 * perthread_get - get the local perthread variable
 * @var: the perthread variable
 *
 * Returns a perthread variable.
 */
#define perthread_get(var)					\
	(*((typeof(__perthread_##var) *)(__perthread_get(&__perthread_##var))))

/**
 * thread_is_active - is the thread initialized?
 * @cpu: the cpu number
 *
 * Returns true if yes, false if no.
 */
#define thread_is_active(cpu)					\
	(perthread_offsets[cpu] != NULL)

static inline int __thread_next_active(int cpu)
{
	while (cpu < cpu_count) {
		if (thread_is_active(++cpu))
			return cpu;
	}

	return cpu;
}

/**
 * for_each_thread - iterates over each thread
 * @cpu: an integer to store the cpu
 */
#define for_each_thread(cpu)					\
	for ((cpu) = -1; (cpu) = __thread_next_active(cpu), (cpu) < cpu_count;)

extern __thread unsigned int thread_cpu_id;
extern __thread unsigned int thread_numa_node;
