/*
 * lrpc.h - shared memory communication channels
 *
 * This design is inspired by Barrelfish, which in turn was based on Brian
 * Bershad's earlier LRPC work. The goal here is to minimize cache misses to
 * the maximum extent possible.
 *
 * Beyond all the usual tricks, we employ a couple extra optimizations:
 * 1.) Messages are kept small and fixed-size, with the option to include larger
 * payloads out-of-band. This can have huge benefits when much of the data is
 * never touched, like with network packets.
 * 2.) Four messages are packed in a cache line and flow control coherence
 * traffic is agressively amortized. Because we were able to keep everything so
 * small, as load increases, cache misses should converge to a level below one
 * miss per message.
 */

#pragma once

#include <base/stddef.h>
#include <base/assert.h>
#include <base/atomic.h>

struct lrpc_msg {
	uint32_t	cmd;
	uint32_t	group;
	void		*data;
};

#define LRPC_DONE_PARITY	(1 << 31)
#define LRPC_CMD_MASK		(~LRPC_DONE_PARITY)

struct lrpc_chan {
	struct lrpc_msg	*tbl;
	uint32_t	*recv_head_wb;
	uint32_t	recv_pos;
	uint32_t	send_head;
	uint32_t	send_tail;
	uint32_t	size;
};

static inline uint32_t lrpc_mask(struct lrpc_chan *chan)
{
	assert(is_power_of_two(chan->size));
	return chan->size - 1;
}

extern bool __lrpc_send_slow(struct lrpc_chan *chan, uint32_t cmd,
			     uint32_t group, void *ptr);

/**
 * lrpc_send - sends a message on the channel
 * @chan: the channel
 * @cmd: the command to send
 * @group: the flow group
 * @data: the data payload
 *
 * Returns true if successful, otherwise the channel is full.
 */
static inline bool lrpc_send(struct lrpc_chan *chan, uint32_t cmd,
			     uint32_t group, void *data)
{
	struct lrpc_msg *dst;

	assert(!(cmd & LRPC_DONE_PARITY));

	if (unlikely(chan->send_tail - chan->send_head >= chan->size))
		return __lrpc_send_slow(chan, cmd, group, data);

	dst = &chan->tbl[chan->send_tail & lrpc_mask(chan)];
	dst->group = group;
	dst->data = data;

	cmd |= (chan->send_tail++ & chan->size) ? 0 : LRPC_DONE_PARITY;
	store_release(&dst->cmd, cmd);
	return true;
}

/**
 * lrpc_recv - receives a message on the channel
 * @chan: the channel
 * @cmd_out: a pointer to store the received command
 * @group_out: a pointer to store the flow group
 * @data_out: a pointer to store the received payload
 *
 * Returns true if successful, otherwise the channel is empty.
 */
static inline bool lrpc_recv(struct lrpc_chan *chan, uint32_t *cmd_out,
			     uint32_t *group_out, void **data_out)
{
        struct lrpc_msg *m = &chan->tbl[chan->recv_pos & lrpc_mask(chan)];
        uint32_t parity = (chan->recv_pos & chan->size) ?
			  0 : LRPC_DONE_PARITY;
	uint32_t cmd;

	cmd = load_acquire(&m->cmd);
        if ((cmd & LRPC_DONE_PARITY) != parity)
		return false;
	chan->recv_pos++;

	*cmd_out = cmd & LRPC_CMD_MASK;
	*group_out = m->group;
	*data_out = m->data;
	store_release(chan->recv_head_wb, chan->recv_pos);
	return true;
}

/**
 * lrpc_get_cached_send_window - retrieves the last known number of slots
 * available for sending
 * @chan: the channel
 *
 * This variant doesn't cause coherence traffic but may return out of date
 * information.
 *
 * Returns the last known number of slots left available for sending.
 */
static inline uint32_t lrpc_get_cached_send_window(struct lrpc_chan *chan)
{
	return chan->size - chan->send_tail + chan->send_head;
}

/**
 * lrpc_get_send_window - retrieves the number of slots available for
 * sending
 * @chan: the channel
 *
 * Returns the number of slots left available for sending.
 */
static inline uint32_t lrpc_get_send_window(struct lrpc_chan *chan)
{
	chan->send_head = load_acquire(chan->recv_head_wb);
	return lrpc_get_cached_send_window(chan);
}

extern int lrpc_init(struct lrpc_chan *chan, struct lrpc_msg *tbl,
		     unsigned int size, uint32_t *recv_head_wb);
