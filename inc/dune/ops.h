/*
 * ops.h - useful x86 opcodes
 */

#pragma once

#include <ix/stddef.h>

/* CPUID Flags. */
#define CPUID_FLAG_FPU          0x1             /* Floating Point Unit. */
#define CPUID_FLAG_VME          0x2             /* Virtual Mode Extensions. */
#define CPUID_FLAG_DE           0x4             /* Debugging Extensions. */
#define CPUID_FLAG_PSE          0x8             /* Page Size Extensions. */
#define CPUID_FLAG_TSC          0x10            /* Time Stamp Counter. */
#define CPUID_FLAG_MSR          0x20            /* Model-specific registers. */
#define CPUID_FLAG_PAE          0x40            /* Physical Address Extensions. */
#define CPUID_FLAG_MCE          0x80            /* Machine Check Exceptions. */
#define CPUID_FLAG_CXCHG8       0x100           /* Compare and exchange 8-byte. */
#define CPUID_FLAG_APIC         0x200           /* On-chip APIC. */
#define CPUID_FLAG_SEP          0x800           /* Fast System Calls. */
#define CPUID_FLAG_MTRR         0x1000          /* Memory Type Range Registers. */
#define CPUID_FLAG_PGE          0x2000          /* Page Global Enable.  */
#define CPUID_FLAG_MCA          0x4000          /* Machine Check Architecture. */
#define CPUID_FLAG_CMOV         0x8000          /* Conditional move-instruction. */
#define CPUID_FLAG_PAT          0x10000         /* Page Attribute Table. */
#define CPUID_FLAG_PSE36        0x20000         /* 36-bit Page Size Extensions. */
#define CPUID_FLAG_PSN          0x40000         /* Processor Serial Number. */
#define CPUID_FLAG_CLFL         0x80000         /* CLFLUSH - fixme? */
#define CPUID_FLAG_DTES         0x200000        /* Debug Trace and EMON Store MSRs. */
#define CPUID_FLAG_ACPI         0x400000        /* Thermal Cotrol MSR. */
#define CPUID_FLAG_MMX          0x800000        /* MMX instruction set. */
#define CPUID_FLAG_FXSR         0x1000000       /* Fast floating point save/restore. */
#define CPUID_FLAG_SSE          0x2000000       /* SSE (Streaming SIMD Extensions) */
#define CPUID_FLAG_SSE2         0x4000000       /* SSE2 (Streaming SIMD Extensions - #2) */
#define CPUID_FLAG_SS           0x8000000       /* Selfsnoop. */
#define CPUID_FLAG_HTT          0x10000000      /* Hyper-Threading Technology. */
#define CPUID_FLAG_TM1          0x20000000      /* Thermal Interrupts, Status MSRs. */
#define CPUID_FLAG_IA64         0x40000000      /* IA-64 (64-bit Intel CPU) */
#define CPUID_FLAG_PBE          0x80000000      /* Pending Break Event. */

/* from xv6, created by MIT PDOS */
static inline void cpuid(uint32_t info, uint32_t *eaxp,
                         uint32_t *ebxp, uint32_t *ecxp,
                         uint32_t *edxp)
{
	uint32_t eax, ebx, ecx, edx;
	asm volatile("cpuid"
		   : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
		   : "a" (info));
	if (eaxp)
		*eaxp = eax;
	if (ebxp)
		*ebxp = ebx;
	if (ecxp)
		*ecxp = ecx;
	if (edxp)
		*edxp = edx;
}

static inline uint64_t rdtsc(void)
{
	uint32_t a, d;
	asm volatile("rdtsc" : "=a" (a), "=d" (d));
	return ((uint64_t) a) | (((uint64_t) d) << 32);
}

static inline uint64_t rdtscp(uint32_t *auxp)
{
	unsigned int a, d, c;
	asm volatile("rdtscp" : "=a" (a), "=d" (d), "=c" (c));
	if (auxp)
		*auxp = c;
	return ((uint64_t) a) | (((uint64_t) d) << 32);
}

static inline uint64_t read_cr3(void)
{
	uint64_t val;
	asm volatile("movq %%cr3, %0" : "=r" (val));
	return val;
}

static inline void write_cr3(uint64_t val)
{
	asm volatile("movq %0, %%cr3" : : "r" (val));
}

#define PCID_COUNT (1 << 12)

#ifdef USE_INVPCID

static inline void invpcid(uint16_t pcid, uint64_t type, uintptr_t la)
{
	struct {
		uint64_t pcid:12;
		uint64_t rsv:52;
		uint64_t la;
	} desc;


	assert(pcid < PCID_COUNT);

	desc.pcid = pcid;
	desc.rsv = 0;
	desc.la = la;

	asm volatile("invpcid (%0), %1" : :
		     "r" (&desc), "r" (type) : "memory");
}

enum {
	INVPCID_TYPE_ADDR = 0,	/* individual address invalidation */
	INVPCID_TYPE_CTX,	/* single context invalidation */
	INVPCID_TYPE_ALL_GLB,	/* all contexts and global translations */
	INVPCID_TYPE_ALL,	/* all contexts except global translations */
};

#endif /* USE_INVPCID */

static inline void flush_tlb_addr(const void *va)
{
	asm volatile("invlpg (%0)" : : "r" (va) : "memory");
}

static inline void set_pgroot(uint16_t pcid, uintptr_t pa, bool inval)
{
	assert(pcid < PCID_COUNT);

	if (inval)
		write_cr3(pa | (uintptr_t) pcid);
	else
		write_cr3(pa | (uintptr_t) pcid | (1UL << 63));
}

static inline void monitor(void const *p, unsigned extensions, unsigned hints)
{
        asm volatile("monitor" : : "a" (p), "c" (extensions), "d" (hints));
}

static inline void mwait(unsigned idle_state, unsigned flags)
{
        asm volatile("mwait" : : "a" (idle_state), "c" (flags));
}

#define IDLE_STATE_C1		0x00 /* ~2 microseconds */
#define IDLE_STATE_C1E		0x01 /* ~10 microseconds */
#define IDLE_STATE_C3		0x10 /* ~33 microseconds */

