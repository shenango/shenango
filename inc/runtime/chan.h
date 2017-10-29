/*
 * chan.h - IPC channel support
 */

#pragma once

#include <base/stddef.h>
#include <base/assert.h>
#include <base/list.h>

struct chan {
	size_t			item_size;
	int			closed;
	spinlock_t		lock;
	uint32_t		cap;

	struct list_head	send_waiters;
	struct list_head	recv_waiters;

	/* for buffered channels */
	uint32_t		head;
	uint32_t		tail;
	void			*buf;
};

typedef struct chan chan_t;

extern int __chan_recv(chan_t *c, void *dst, bool block);
extern int __chan_send(chan_t *c, const void *src, bool block);
extern int chan_create(chan_t *c, size_t item_size, uint32_t cap);
extern void chan_close(chan_t *c);

/**
 * chan_recv - receive an item from the channel
 * @cptr: a pointer to the channel
 * @item: a pointer to the item to receive
 * @block: if true, wait for the next message, otherwise returns -EAGAIN
 *
 * Returns 0 if successful, -EIO if chan is closed, or -EAGAIN if no messages.
 */
#define chan_recv(cptr, item, block)			\
	({assert(sizeof(*item) == (cptr)->item_size);	\
	 __chan_recv(cptr, item, block);})

/**
 * chan_send - send an item to the channel
 * @cptr: a pointer to the channel
 * @item: a pointer to the item to send
 * @block: if true, wait for the next message, otherwise returns -EAGAIN
 *
 * Panics if channel is closed.
 * Returns 0 if successful or -EAGAIN if no messages.
 */
#define chan_send(cptr, item, block)			\
	({assert(sizeof(*item) == (cptr)->item_size);	\
	 __chan_send(cptr, item, block);})
