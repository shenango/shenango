/*
 * rculist.h - support for RCU list data structures
 */

#pragma once

#include <runtime/rcu.h>

struct rcu_hlist_node {
	struct rcu_hlist_node __rcu *next;
	struct rcu_hlist_node * __rcu *pprev;
};

struct rcu_hlist_head {
	struct rcu_hlist_node __rcu *head;
};

/**
 * rcu_hlist_init_head - initializes an RCU hlist
 * @h: the list head
 */
static inline void rcu_hlist_init_head(struct rcu_hlist_head *h)
{
	RCU_INIT_POINTER(h->head, NULL);
}

/**
 * rcu_hlist_add_head - adds a node to the head of an RCU hlist
 * @h: the list head
 * @n: the node to add
 */
static inline void rcu_hlist_add_head(struct rcu_hlist_head *h,
				      struct rcu_hlist_node *n)
{
	struct rcu_hlist_node *head = h->head;
	RCU_INIT_POINTER(n->next, head);
	n->pprev = &h->head;
	rcu_assign_pointer(h->head, n);
	if (head)
		head->pprev = &n->next;
}

/**
 * rcu_hlist_del - removes a node from an RCU hlist
 * @n: the node to remove
 */
static inline void rcu_hlist_del(struct rcu_hlist_node *n)
{
	rcu_assign_pointer(*n->pprev, n->next);
	if (n->next)
		n->next->pprev = n->pprev;
}

/**
 * rcu_hlist_empty - returns true if the RCU hlist is empty
 * @h: the list head
 * @check: proof that a lock is held
 *
 * If @check is false, must be in an RCU critical section.
 */
static inline bool rcu_hlist_empty(struct rcu_hlist_head *h, bool check)
{
	return rcu_dereference_protected(h->head, check) == NULL;
}

#define rcu_hlist_entry(n, type, member) container_of(n, type, member)

#define rcu_hlist_for_each(h, pos, check)				\
	for ((pos) = rcu_dereference_protected((h)->head, check); (pos);\
	     (pos) = rcu_dereference_protected((pos)->next, check))

#define rcu_hlist_for_each_safe(h, pos, tmp, check)			\
	for ((pos) = rcu_dereference_protected((h)->head, check); (pos)	\
	     && ((tmp) = rcu_dereference_protected((pos)->next, check), 1);\
	     (pos) = (tmp))
