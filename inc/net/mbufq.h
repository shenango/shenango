/*
 * mbufq.h - singly-linked queue of MBUFs
 */

#pragma once

#include <net/mbuf.h>

struct mbuf;

struct mbufq {
	struct mbuf *head, *tail;
};

/**
 * mbufq_push_tail - push an mbuf to the tail of the queue
 * @q: the mbuf queue
 * @m: the mbuf to push
 */
static inline void mbufq_push_tail(struct mbufq *q, struct mbuf *m)
{
	m->next = NULL;
	if (!q->head) {
		q->head = q->tail = m;
		return;
	}
	q->tail->next = m;
	q->tail = m;
}

/**
 * mbufq_pop_head - pop an mbuf from the head of the queue
 * @q: the mbuf queue
 *
 * Returns an mbuf or NULL if the queue is empty.
 */
static inline struct mbuf *mbufq_pop_head(struct mbufq *q)
{
	struct mbuf *head = q->head;
	if (!head)
		return NULL;
	q->head = head->next;
	return head;
}

/**
 * mbufq_peak_head - reads the head of the queue without popping
 * @q: the mbuf queue
 *
 * Returns an mbuf or NULL if the queue is empty.
 */
static inline struct mbuf *mbufq_peak_head(struct mbufq *q)
{
	return q->head;
}

/**
 * mbufq_merge_to_tail - merges a queue to the end of another queue
 * @dst: the destination queue (will contain all the mbufs)
 * @src: the source queue (will become empty)
 */
static inline void mbufq_merge_to_tail(struct mbufq *dst, struct mbufq *src)
{
	if (!src->head)
		return;
	if (!dst->head)
		dst->head = src->head;
	else 
		dst->tail->next = src->head;
	dst->tail = src->tail;
	src->head = NULL;
}

/**
 * mbufq_empty - returns true if the queue is empty
 */
static inline bool mbufq_empty(struct mbufq *q)
{
	return q->head == NULL;
}

/**
 * mbufq_release - frees all the mbufs in the queue
 * @q: the queue to release
 */
static inline void mbufq_release(struct mbufq *q)
{
	struct mbuf *m;
	while (true) {
		m = mbufq_pop_head(q);
		if (!m)
			break;
		mbuf_free(m);
	}
}

/**
 * mbufq_init - initializes a queue
 * @q: the mbuf queue to initialize
 */
static inline void mbufq_init(struct mbufq *q)
{
	q->head = NULL;
}
