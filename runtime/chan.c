/*
 * chan.c - CSP channel support
 *
 * This is heavily inspired by the Go programming language.
 */

#include <string.h>

#include <base/lock.h>
#include <base/log.h>
#include <base/atomic.h>
#include <runtime/smalloc.h>
#include <runtime/thread.h>
#include <runtime/chan.h>

#include "defs.h"

static inline void *chan_buf_pos(chan_t *c, uint32_t idx)
{
	return (char *)c->buf + idx * c->item_size;
}

int __chan_recv(chan_t *c, void *dst, bool block)
{
	thread_t *th = NULL;
	const void *src;

	spin_lock(&c->lock);

	if (c->head != c->tail) {
		/* first try to receive from buffer */
		int idx = c->tail++ % c->cap;
		src = chan_buf_pos(c, idx);
	} else if (c->closed) {
		/* Buffer is empty and there are no future senders */
		spin_unlock(&c->lock);
		return -EIO;
	} else if (!list_empty(&c->send_waiters)) {
		/* then try to receive directly from waiting sender */
		th = list_pop(&c->send_waiters, thread_t, link);
		src = th->chan_buf;
	} else {
		/* finally, wait for the next sender */
		if (!block) {
			spin_unlock(&c->lock);
			return -EAGAIN;
		}

		th = thread_self();
		th->chan_closed = false;
		th->chan_buf = dst;
		list_add_tail(&c->recv_waiters, &th->link);
		thread_park_and_unlock(&c->lock);

		assert(th == thread_self());
		return th->chan_closed ? -EIO : 0;
	}

	memcpy(dst, src, c->item_size);
	wmb();
	if (th)
		thread_ready(th);
	spin_unlock(&c->lock);

	return 0;
}

int __chan_send(chan_t *c, const void *src, bool block)
{
	thread_t *th = NULL;
	void *dst;

	spin_lock(&c->lock);
	if (c->closed)
		panic("cannot send on a closed channel");

	if (!list_empty(&c->recv_waiters)) {
		/* first try a waiting receiver */
		th = list_pop(&c->recv_waiters, thread_t, link);
		dst = th->chan_buf;
	} else if (c->head - c->tail < c->cap) {
		/* then try to send to the buffer */
		int idx = c->head++ % c->cap;
		dst = chan_buf_pos(c, idx);
	} else {
		/* finally, wait for the next receiver */
		if (!block) {
			spin_unlock(&c->lock);
			return -EAGAIN;
		}

		th = thread_self();
		th->chan_closed = false;
		th->chan_buf = (void *)src;
		list_add_tail(&c->send_waiters, &th->link);
		thread_park_and_unlock(&c->lock);

		assert(th == thread_self());
		return 0;
	}

	memcpy(dst, src, c->item_size);
	wmb();
	if (th)
		thread_ready(th);
	spin_unlock(&c->lock);

	return 0;
}

/**
 * chan_create - initializes a channel
 * @c: the channel to initialize
 * @item_size; the size of each item in the channel
 * @cap: the capacity of the channel (can be 0 for unbuffered)
 *
 * Returns 0 if successful, or -ENOMEM if out of memory.
 */
int chan_create(chan_t *c, size_t item_size, uint32_t cap)
{
	c->item_size = item_size;
	c->closed = false;
	spin_lock_init(&c->lock);
	c->cap = cap;

	list_head_init(&c->recv_waiters);
	list_head_init(&c->send_waiters);

	c->head = c->tail = 0;
	if (cap > 0) {
		c->buf = smalloc(cap * item_size);
		if (!c->buf)
			return -ENOMEM;
	} else {
		c->buf = NULL;
	}

	return 0;
}

/**
 * chan_close - closes a channel, freeing any underlying memory
 * @c: the channel to close
 *
 * This function will wake any receivers still blocked on the channel. A
 * channel cannot be closed if there are still blocking senders. Moreover,
 * new messages cannot be send on a channel once it has been closed.
 */
void chan_close(chan_t *c)
{
	thread_t *th;

	spin_lock(&c->lock);
	c->closed = true;
	if (!list_empty(&c->send_waiters))
		panic("can't send on a closed channel");
	while (!list_empty(&c->recv_waiters)) {
		th = list_pop(&c->recv_waiters, thread_t, link);
		th->chan_closed = true;
		thread_ready(th);
	}
	spin_unlock(&c->lock);

	if (c->buf)
		sfree(c->buf);
}
