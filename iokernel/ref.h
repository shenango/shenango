/*
 * ref.h - generic support for reference counts
 *
 * This implementation is inspired by the following paper:
 * Kroah-Hartman, Greg, kobjects and krefs. Linux Symposium 2004
 *
 * This version doesn't use atomics.
 */

#pragma once

#include <base/stddef.h>

struct ref {
	int cnt;
};

/**
 * ref_init - initializes the reference count to one
 * @ref: the kref
 */
static inline void
ref_init(struct ref *ref)
{
	ref->cnt = 1;
}

/**
 * ref_get - atomically increments the reference count
 * @ref: the kref
 */
static inline void
ref_get(struct ref *ref)
{
	assert(ref->cnt > 0);
	ref->cnt++;
}

/**
 * ref_put - atomically decrements the reference count, releasing the object
 *	     when it reaches zero
 * @ref: the ref
 * @release: a pointer to the release function
 */
static inline void
ref_put(struct ref *ref, void (*release)(struct ref *ref))
{
	assert(release);
	if (--ref->cnt == 0)
		release(ref);
}
