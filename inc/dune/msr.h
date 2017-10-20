/*
 * msr.h - x86 Machine-specific Register (MSR) support
 *
 * Based on code from XV6, created by MIT PDOS.
 */

#pragma once

#include <base/types.h>

static inline uint64_t rdmsr(uint64_t msr)
{
	uint32_t low, high;
	asm volatile("rdmsr" : "=a" (low), "=d" (high) : "c" (msr));
	return (uint64_t)low | ((uint64_t)high << 32);
}

static inline void wrmsr(uint64_t msr, uint64_t val)
{
	uint32_t low = (val & 0xffffffff);
	uint32_t high = (val >> 32);
	asm volatile("wrmsr" : : "c" (msr), "a" (low), "d" (high) : "memory");
}

// FS/GS base registers
#define MSR_FS_BASE     0xc0000100
#define MSR_GS_BASE     0xc0000101
#define MSR_GS_KERNBASE 0xc0000102

// SYSCALL and SYSRET registers
#define MSR_STAR        0xc0000081
#define MSR_LSTAR       0xc0000082
#define MSR_CSTAR       0xc0000083
#define MSR_SFMASK      0xc0000084

#define MSR_INTEL_MISC_ENABLE 0x1a0
#define MISC_ENABLE_PEBS_UNAVAILABLE (1<<12) // Read-only

// AMD performance event-select registers
#define MSR_AMD_PERF_SEL0  0xC0010000
#define MSR_AMD_PERF_SEL1  0xC0010001
#define MSR_AMD_PERF_SEL2  0xC0010002
#define MSR_AMD_PERF_SEL3  0xC0010003
// AMD performance event-count registers
#define MSR_AMD_PERF_CNT0  0xC0010004
#define MSR_AMD_PERF_CNT1  0xC0010005
#define MSR_AMD_PERF_CNT2  0xC0010006
#define MSR_AMD_PERF_CNT3  0xC0010007

// Intel performance event-select registers
#define MSR_INTEL_PERF_SEL0 0x00000186
// Intel performance event-count registers
#define MSR_INTEL_PERF_CNT0 0x000000c1
#define MSR_INTEL_PERF_GLOBAL_STATUS   0x38e
#define PERF_GLOBAL_STATUS_PEBS        (1ull << 62)
#define MSR_INTEL_PERF_GLOBAL_CTRL     0x38f
#define MSR_INTEL_PERF_GLOBAL_OVF_CTRL 0x390

#define MSR_INTEL_PERF_CAPABILITIES 0x345 // RO
#define MSR_INTEL_PEBS_ENABLE       0x3f1
#define MSR_INTEL_PEBS_LD_LAT       0x3f6
#define MSR_INTEL_DS_AREA           0x600

// Common event-select bits
#define PERF_SEL_USR        (1ULL << 16)
#define PERF_SEL_OS         (1ULL << 17)
#define PERF_SEL_EDGE       (1ULL << 18)
#define PERF_SEL_INT        (1ULL << 20)
#define PERF_SEL_ENABLE     (1ULL << 22)
#define PERF_SEL_INV        (1ULL << 23)
#define PERF_SEL_CMASK_SHIFT 24

// APIC Base Address Register MSR
#define MSR_APIC_BAR        0x0000001b
#define APIC_BAR_XAPIC_EN   (1 << 11)
#define APIC_BAR_X2APIC_EN  (1 << 10)

#define MSR_PKG_ENERGY_STATUS 0x00000611

static inline uintptr_t getfsbase(void)
{
#ifdef USE_RDWRGSFS
	uintptr_t base;
	asm volatile("rdfsbase %0" : "=r"(base));
	return base;
#else
	return rdmsr(MSR_FS_BASE);
#endif
}

static inline uintptr_t getgsbase(void)
{
#ifdef USE_RDWRGSFS
	uintptr_t base;
	asm volatile("rdgsbase %0" : "=r"(base));
	return base;
#else
	return rdmsr(MSR_GS_BASE);
#endif
}

static inline void setfsbase(uintptr_t base)
{
#ifdef USE_RDWRGSFS
	asm volatile("wrfsbase %0" : : "r"(base));
#else
	wrmsr(MSR_FS_BASE, base);
#endif
}

static inline void setgsbase(uintptr_t base)
{
#ifdef USE_RDWRGSFS
	asm volatile("wrgsbase %0" : : "r"(base));
#else
	wrmsr(MSR_GS_BASE, base);
#endif
}

static inline void setgskernbase(uintptr_t base)
{
	assert(!is_irq_enabled());

	asm volatile("swapgs");
#ifdef USE_RDWRGSFS
	asm volatile("wrgsbase %0" : : "r"(base));
#else
	wrmsr(MSR_GS_BASE, base);
#endif
	asm volatile("swapgs");
}
