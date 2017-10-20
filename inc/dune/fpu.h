/*
 * fpu.h - x86 floating point, MMX, SSE, and AVX support for Dune
 */

#pragma once

#include <base/types.h>

struct fxsave_area {
	uint16_t cwd;
	uint16_t swd;
	uint16_t twd;
	uint16_t fop;
	uint64_t rip;
	uint64_t rdp;
	uint32_t mxcsr;
	uint32_t mxcsr_mask;
	uint32_t st_regs[32];   // 8 128-bit FP registers
	uint32_t xmm_regs[64];  // 16 128-bit XMM registers
	uint32_t padding[24];
} __attribute__((packed));

struct xsave_header {
	uint64_t xstate_bv;
	uint64_t xcomp_bv;
	uint64_t reserved_zero;
	uint64_t reserved[5];
} __attribute__((packed));

struct xsave_area {
	struct fxsave_area	fxsave;
	struct xsave_header	header;
	uint32_t		ymm_regs[64]; // extends XMM registers to 256-bit
	/* FIXME: check CPUID, could be other extensions in the future */
} __attribute__((packed, aligned(64)));

struct fpu_area {
	/* we only support xsave, since it's available in nehalem and later */
	struct xsave_area	xsave;
};

static inline void fpu_xsave(struct fpu_area *fp, uint64_t mask)
{
	uint32_t lmask = mask;
	uint32_t umask = mask >> 32;

	asm volatile("xsaveq %0\n\t" : "=m"(fp->xsave) :
		     "a"(lmask), "d"(umask) :
		     "memory");
}

static inline void fpu_xsaveopt(struct fpu_area *fp, uint64_t mask)
{
	uint32_t lmask = mask;
	uint32_t umask = mask >> 32;

	asm volatile("xsaveoptq %0\n\t" : "=m"(fp->xsave) :
		     "a"(lmask), "d"(umask) :
		     "memory");
}

static inline void fpu_xrstor(struct fpu_area *fp, uint64_t mask)
{
	uint32_t lmask = mask;
	uint32_t umask = mask >> 32;

	asm volatile("xrstorq %0\n\t" : : "m"(fp->xsave),
		     "a"(lmask), "d"(umask) :
		     "memory");
}

/*
 * fpu_init - initializes an fpu area
 * @fp: the fpu area
 */
static inline void fpu_init(struct fpu_area *fp)
{
	fp->xsave.header.xstate_bv = 0;
	fp->xsave.header.xcomp_bv = 0;
	fp->xsave.header.reserved_zero = 0;
	fp->xsave.fxsave.cwd = 0x37f;
	fp->xsave.fxsave.mxcsr = 0x1f80;
}

/*
 * fpu_load - loads an fpu area into fpu registers
 * @fp: the fpu area
 */
static inline void fpu_load(struct fpu_area *fp)
{
	fpu_xrstor(fp, -1);
}

/*
 * fpu_save - saves fpu registers to an fpu area
 * @fp: the fpu area
 *
 * WARNING: Do not call this function on a memory region
 * that was not previously loaded with fpu_load().
 *
 * If you do, register state corruption might be possible. See
 * "XSAVEOPT Usage Guidlines" under the XSAVEOPT instruction
 * description in the Intel Manual Instruction Set Reference
 * for more details.
 */
static inline void fpu_save(struct fpu_area *fp)
{
	// FIXME: need to check CPUID because only
	// sandybridge and later support XSAVEOPT
	fpu_xsaveopt(fp, -1);
}

/*
 * fpu_save_safe - saves an fpu area from CPU registers
 * @fp: the fpu area
 *
 * Works under all conditions, but may be slower.
 */
static inline void fpu_save_safe(struct fpu_area *fp)
{
	fpu_xsave(fp, -1);
}

