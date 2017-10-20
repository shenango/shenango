/*
 * stat.h - statistics counter support
 */

#pragma once

#include <base/stddef.h>
#include <base/thread.h>
#include <base/limits.h>
#include <base/list.h>


/*
 * Generic stat counter API
 */

struct stat_entry;
typedef uint64_t (*stat_collect_fn_t)(struct stat_entry *e, unsigned long data);

struct stat_entry {
	const char		*name;
	stat_collect_fn_t	handler;
	unsigned long		data;
	struct list_node	link;
};

extern int stat_register(struct stat_entry *entry);
extern void stat_unregister(struct stat_entry *entry);
extern uint64_t stat_collect(struct stat_entry *entry);

struct stat_result {
	const char		*name;
	uint64_t		val;
};

extern int stat_collect_all(struct stat_result *results_out, int capacity);
extern void stat_print_all(void);


/*
 * Some common stat collectors
 */

extern uint64_t __stat_var_collect(struct stat_entry *e, unsigned long data);
extern uint64_t __stat_perthread_var_collect(struct stat_entry *e,
					     unsigned long data);

/**
 * stat_register_var - registers a stat backed by a uint64_t
 * @entry: the stat entry struct to register
 * @name: a human-readable name for the stat
 * @val: the uint64_t value that stores the count
 *
 * Returns 0 if successful, otherwise fail.
 */
static inline int
stat_register_var(struct stat_entry *entry, const char *name, uint64_t *val)
{
	entry->name = name;
	entry->handler = __stat_var_collect;
	entry->data = (unsigned long)val;
	return stat_register(entry);
}

/**
 * stat_register_perthread_var - registers a stat backed by a perthread uint64_t
 * @entry: the stat entry struct to register
 * @name: a human-readable name for the stat
 * @val: the perthread uint64_t value that stores the count
 *
 * Returns 0 if successful, otherwise fail.
 */
static inline int
stat_register_perthread_var(struct stat_entry *entry, const char *name,
			    uint64_t __perthread *val)
{
	entry->name = name;
	entry->handler = __stat_perthread_var_collect;
	entry->data = (__force unsigned long)val;
	return stat_register(entry);
}
