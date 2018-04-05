/*
 * gen.h - shared generation numbers
 */

#pragma once

#include <stdint.h>

#include <base/stddef.h>

/* describes a generation number */
struct gen_num {
	uint32_t		prev_gen;
	volatile uint32_t	*gen;
};

/*
 * gen_active - used by a writer to indicate that a generation is ongoing
 */
static inline void gen_active(struct gen_num *g)
{
	if (*g->gen == 0)
		*g->gen = g->prev_gen + 1;
}

/*
 * gen_inactive - used by a writer to indicate that we are between generations
 */
static inline void gen_inactive(struct gen_num *g)
{
	if (*g->gen != 0) {
		g->prev_gen = *g->gen;
		*g->gen = 0;
	}
}

/*
 * gen_in_same_gen - used by a reader to determine if we are in the same
 * generation as last time we checked
 *
 * Returns true if we are in the same generation as last time, false if we are
 * in a different generation or are between generations.
 */
static inline bool gen_in_same_gen(struct gen_num *g)
{
	uint32_t current_gen = *g->gen;
	bool unchanged;

	unchanged = (current_gen != 0) && (current_gen == g->prev_gen);
	g->prev_gen = current_gen;

	return unchanged;
}

/*
 * gen_init - initialize a shared generation number
 */
static inline void gen_init(struct gen_num *g, uint32_t *gen)
{
	g->prev_gen = 0;
	g->gen = gen;
}
