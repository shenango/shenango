/*
 * stat.h - statistics counter support
 *
 * TODO: Use RCU for registered stat list.
 */

#include <base/stat.h>
#include <base/lock.h>
#include <base/log.h>


/*
 * stat infrastructure
 */

/* a list and count of registered stats */
static DEFINE_SPINLOCK(stat_lock);
static LIST_HEAD(stat_list);
static int stat_count;

/**
 * stat_register - registers a statistics counter
 * @entry: the stat entry to register
 *
 * Returns 0 if successful, otherwise -ENOSPC if the limit on stat counters was
 * reached.
 */
int stat_register(struct stat_entry *entry)
{
	spin_lock(&stat_lock);
	if (stat_count >= NSTAT) {
		spin_unlock(&stat_lock);
		return -ENOSPC;
	}

	list_add_tail(&stat_list, &entry->link);
	stat_count++;
	spin_unlock(&stat_lock);
	return 0;
}

/**
 * stat_unregister - unregisters a statistics counter
 * @entry: the stat entry to unregister
 */
void stat_unregister(struct stat_entry *entry)
{
	spin_lock(&stat_lock);
	list_del_from(&stat_list, &entry->link);
	stat_count--;
	spin_unlock(&stat_lock);
}

/**
 * stat_collect - collects the value of a statistics counter
 * @entry: the stat entry to collect
 *
 * Returns the uint64_t value of the statistics counter.
 */
uint64_t stat_collect(struct stat_entry *entry)
{
	return entry->handler(entry, entry->data);
}

/**
 * stat_collect_all - collects the values of all registered stat counters
 * @results_out: a table to store the results
 * @capacity: the size of the table
 *
 * If @capacity is NSTAT in size, then all stats will fit.
 *
 * Returns the number of collected stats.
 */
int stat_collect_all(struct stat_result *results_out, int capacity)
{
	struct stat_entry *pos;
	int idx = 0;

	spin_lock(&stat_lock);
	list_for_each(&stat_list, pos, link) {
		struct stat_result *result = &results_out[idx++];
		result->name = pos->name;
		result->val = stat_collect(pos);
		if (idx >= capacity)
			break;
	}
	spin_unlock(&stat_lock);
	return idx;
}

/**
 * stat_print_all - prints the values of all registered stat counters
 *
 * Useful for debugging.
 */
void stat_print_all(void)
{
	struct stat_result results[NSTAT];
	int i, count;

	count = stat_collect_all(results, NSTAT);
	log_info("stat: dumping stat counters");
	for (i = 0; i < count; i++)
		log_info("\t%s:%ld\n", results[i].name, results[i].val);
}


/*
 * stat collectors
 */

uint64_t __stat_var_collect(struct stat_entry *e, unsigned long data)
{
	return *(uint64_t *)data;
}

uint64_t __stat_perthread_var_collect(struct stat_entry *e, unsigned long data)
{
	uint64_t val = 0;
	int cpu;

	for_each_thread(cpu) {
		val += *(uint64_t *)((uintptr_t)perthread_offsets[cpu] +
				     (uintptr_t)data);
	}
	return val;
}
