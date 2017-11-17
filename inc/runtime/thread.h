/*
 * thread.h - support for user-level threads
 */

#pragma once

#include <base/types.h>

struct thread;
typedef void (*thread_fn_t)(void *arg);
typedef struct thread thread_t;

/*
 * Low-level routines, usually don't call these directly. Instead use the
 * primitives provided in runtime/sync.h.
 */
extern void thread_park_and_unlock(spinlock_t *lock);
extern void thread_ready(thread_t *thread);

extern __thread thread_t *__self;

/**
 * thread_self - gets the currently running thread
 */
static inline thread_t *thread_self(void)
{
	return __self;
}

extern void thread_yield(void);
extern int thread_spawn(thread_fn_t fn, void *arg);
extern int thread_spawn_with_data(thread_fn_t fn, size_t len, void **arg);
extern void thread_exit(void) __noreturn;

/* main initialization */
extern int runtime_init(thread_fn_t main_fn, void *arg, unsigned int cores);
