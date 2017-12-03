/*
 * atomic.h - utilities for atomic memory ops
 */

#pragma once

#include <base/compiler.h>
#include <base/assert.h>

/**
 * mb - a memory barrier
 *
 * Ensures all loads and stores before the barrier complete
 * before all loads and stores after the barrier.
 */
#define mb() asm volatile("mfence" ::: "memory")

/**
 * rmb - a read memory barrier
 *
 * Ensures all loads before the barrier complete before
 * all loads after the barrier.
 */
#define rmb() barrier()

/**
 * wmb - a write memory barrier
 *
 * Ensures all stores before the barrier complete before
 * all stores after the barrier.
 */
#define wmb() barrier()

/**
 * store_release - store a native value with release fence semantics
 * @p: the pointer to store
 * @v: the value to store
 */
#define store_release(p, v)			\
do {						\
	BUILD_ASSERT(type_is_native(*p));	\
	barrier();				\
	ACCESS_ONCE(*p) = v;			\
} while (0)

/**
 * load_acquire - load a native value with acquire fence semantics
 * @p: the pointer to load
 */
#define load_acquire(p)				\
({						\
	BUILD_ASSERT(type_is_native(*p));	\
	typeof(*p) __p = ACCESS_ONCE(*p);	\
	barrier();				\
	__p;					\
})

/**
 * load_consume - load a native value with consume fence semantics
 * @p: the pointer to load
 */
#define load_consume(p)				\
({						\
	BUILD_ASSERT(type_is_native(*p));	\
	typeof(*p) __p = ACCESS_ONCE(*p);	\
	barrier();				\
	__p;					\
})
