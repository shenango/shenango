/*
 * msg.h - shared memory communication between the IOHUB and clients
 */

#pragma once

#include <limits.h>

#include <base/stddef.h>
#include <base/atomic.h>
#include <base/lrpc.h>


/*
 * Shared memory pointer support. These are pointers that are passed across
 * address spaces, so the mapped regions will have different base offsets.
 */

typedef uintptr_t shmptr_t;

/* shared memory pointers have a special non-zero NULL value */
#define SHMPTR_NULL	ULONG_MAX

struct shm_region {
	void		*base;
	size_t		len;
};

/**
 * ptr_to_shmptr - converts a normal pointer to a shared memory pointer
 * @r: the shared memory region the pointer resides in
 * @ptr: the pointer
 *
 * Returns a shared memory pointer.
 */
static inline shmptr_t ptr_to_shmptr(struct shm_region *r, void *ptr)
{
	assert((uintptr_t)r->base <= (uintptr_t)ptr);
	assert((uintptr_t)ptr < (uintptr_t)r->base + r->len);
	return (uintptr_t)ptr - (uintptr_t)r->base;
}

/**
 * shmptr_to_ptr - converts a shared memory pointer to a normal pointer
 * @r: the shared memory region the shared memory pointer resides in
 * @shmptr: the shared memory pointer
 *
 * Returns a normal pointer, or NULL if the shared memory pointer is outside
 * the region.
 */
static inline void *shmptr_to_ptr(struct shm_region *r, shmptr_t shmptr)
{
	assert(r->len != SHMPTR_NULL);
	if (unlikely(shmptr >= r->len))
		return NULL;
	return (void *)(shmptr + (uintptr_t)r->base);
}


/*
 * message chains are singly-linked lists of commands passed over shared memory.
 */

struct msg_chain {
	unsigned int	type;
	unsigned int	pad;
	shmptr_t	next;
};

/* For performance, we intend for reading the chain to pull in command data */
BUILD_ASSERT(sizeof(struct msg_chain) <= CACHE_LINE_SIZE);

enum {
	MSG_CHAIN_TYPE_PACKET = 0,
	MSG_CHAIN_TYPE_PACKET_COMPLETION,
};

/**
 * msg_chain_get_next - retrieves the next request in the chain
 * @r: the shared memory region the chains reside in
 * @c: the current request
 *
 * Returns a request, or NULL if at the end of the chain or invalid.
 */
static inline struct msg_chain *
msg_chain_get_next(struct shm_region *r, struct iochain *c)
{
	return (struct msg_chain *)shmptr_to_ptr(load_acquire(&c->next));
}

/**
 * msg_chain_set_next - appends the next request to the chain
 * @r: the shared memory region the chains reside in
 * @c: the current request
 * @next: the next request
 */
static inline void
msg_chain_set_next(struct shm_region *r, struct iochain *c,
		   struct msg_chain *next)
{
	shmptr_t shmptr = ptr_to_shmptr(next);
	assert(c->next == SHMPTR_NULL);
	return store_release(&c->next, shmptr);
}


/*
 * Support for LRPC messages between the IOHUB and the client.
 */

struct msg_packet {
	struct msg_chain chain;		/* chains the next command */
	unsigned int	len;		/* the length of the payload */
	unsigned int	rss_hash;	/* the HW RSS 5-tuple hash */
	unsigned int	csum_type;	/* the type of checksum */
	unsigned int	csum;		/* 16-bit one's complement */
	char		payload[];	/* packet data */
};

/* possible lrpc commands */
enum {
	MSG_TYPE_START_CHAIN = 0,
	MSG_TYPE_COMPLETE_CHAIN,
};
