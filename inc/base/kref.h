/*
 * kref.h - generic support for reference counts
 *
 * This implementation is inspired by the following paper:
 * Kroah-Hartman, Greg, kobjects and krefs. Linux Symposium 2004
 */

#pragma once

#include <base/stddef.h>
#include <base/atomic.h>

struct kref {
	atomic_t cnt;
};

/**
 * kref_init - initializes the reference count to one
 * @ref: the kref
 */
static inline void
kref_init(struct kref *ref)
{
	atomic_write(&ref->cnt, 1);
}

/**
 * kref_initn - initializes the reference count to @n
 * @ref: the kref
 * @n: the initial reference count
 */
static inline void
kref_initn(struct kref *ref, int n)
{
	atomic_write(&ref->cnt, n);
}

/**
 * kref_get - atomically increments the reference count
 * @ref: the kref
 */
static inline void
kref_get(struct kref *ref)
{
	assert(atomic_read(&ref->cnt) > 0);
	atomic_inc(&ref->cnt);
}

/**
 * kref_put - atomically decrements the reference count, releasing the object
 *	      when it reaches zero
 * @ref: the kref
 * @release: a pointer to the release function
 */
static inline void
kref_put(struct kref *ref, void (*release)(struct kref *ref))
{
	assert(release);
	if (atomic_dec_and_test(&ref->cnt))
		release(ref);
}

/**
 * kref_released - has this kref been released?
 * @ref: the kref
 *
 * WARNING: this is unsafe without additional synchronization. For example, use
 * this function while holding a lock that prevents the release() function from
 * removing the object from the data structure you are accessing.
 *
 * Returns true if the reference count has dropped to zero.
 */
static inline bool
kref_released(struct kref *ref)
{
	return atomic_read(&ref->cnt) == 0;
}
