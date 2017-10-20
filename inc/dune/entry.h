/*
 * entry.h - routines for entering and exiting the kernel
 */

#pragma once

#include <base/stddef.h>

/* the base address of the linux kernel vdso mapping */
extern uintptr_t entry_vdso_base;

/* asm entry routines */
extern const char syscall_enter[];
extern const char syscall_enter_end[];
extern const char trap_entry_tbl[];
extern const char vsyscall_page[];

#define TRAP_ENTRY_SIZE	16

/*
 * We use the same general GDT layout as Linux so that can we use
 * the same syscall MSR values. In practice only code segments
 * matter, since ia-32e mode ignores most of segment values anyway,
 * but just to be extra careful we match data as well.
 */
#define GD_KT           0x10
#define GD_KD           0x18
#define GD_UD           0x28
#define GD_UT           0x30
#define GD_TSS          0x38
#define GD_TSS2         0x40
#define GDT_ENTRIES 9

struct env_tf {
	/* manually saved, arguments */
	uint64_t rdi;
	uint64_t rsi;
	uint64_t rdx;
	uint64_t rcx;
	uint64_t r8;
	uint64_t r9;
	uint64_t r10;
	uint64_t r11;

	/* saved by C calling conventions */
	uint64_t rbx;
	uint64_t rbp;
	uint64_t r12;
	uint64_t r13;
	uint64_t r14;
	uint64_t r15;

	/* system call number, ret */
	uint64_t rax;

	/* exception frame */
	uint32_t err;
	uint32_t pad1;
	uint64_t rip;
	uint16_t cs;
	uint16_t pad2[3];
	uint64_t rflags;
	uint64_t rsp;
	uint16_t ss;
	uint16_t pad3[3];
} __packed;

#define ARG0(tf)        ((tf)->rdi)
#define ARG1(tf)        ((tf)->rsi)
#define ARG2(tf)        ((tf)->rdx)
#define ARG3(tf)        ((tf)->rcx)
#define ARG4(tf)        ((tf)->r8)
#define ARG5(tf)        ((tf)->r9)

extern void pop_tf(struct env_tf *tf) __noreturn;
extern void pop_tf_user(struct env_tf *tf) __noreturn;
extern void pop_tf_user_fast(struct env_tf *tf) __noreturn;
extern void switch_tf(struct env_tf *curtf, struct env_tf *newtf);

struct entry_percpu {
	void		*percpu_ptr;
	uint64_t	tmp;
	uintptr_t	kfs_base;
	uintptr_t	ufs_base;
	uintptr_t	ugs_base;
	uint64_t	flags;
	void		*thread_stack;
	uint32_t	preempt_cnt;
	uint32_t	pad;
} __packed;

#define ENTRY_FLAG_IN_USER	0x1 /* in usermode? */
#define ENTRY_FLAG_LOAD_USER	0x2 /* restore usermode segs? */

static inline void entry_set_thread_stack(uintptr_t val)
{
	asm("movq %0, %%gs:%c[thread_stack]"
	    : /* no outputs */
	    : "r"(val), [thread_stack]"i"(offsetof(struct entry_percpu, thread_stack))
	    : "memory");
}

static inline uint64_t entry_get_kfs_base(void)
{
	uint64_t val;
	asm("movq %%gs:%c[kfs_base], %0"
	    : "=r"(val)
	    : [kfs_base]"i"(offsetof(struct entry_percpu, kfs_base))
	    : "memory");

	return val;
}

static inline void entry_set_kfs_base(uint64_t val)
{
	asm("movq %0, %%gs:%c[kfs_base]"
	    : /* no outputs */
	    : "r"(val), [kfs_base]"i"(offsetof(struct entry_percpu, kfs_base))
	    : "memory");
}

static inline uint64_t entry_get_ufs_base(void)
{
	uint64_t val;
	asm("movq %%gs:%c[ufs_base], %0"
	    : "=r"(val)
	    : [ufs_base]"i"(offsetof(struct entry_percpu, ufs_base))
	    : "memory");

	return val;
}

static inline void entry_set_ufs_base(uint64_t val)
{
	asm("movq %0, %%gs:%c[ufs_base]"
	    : /* no outputs */
	    : "r"(val), [ufs_base]"i"(offsetof(struct entry_percpu, ufs_base))
	    : "memory");
}

static inline uint64_t entry_get_ugs_base(void)
{
	uint64_t val;
	asm("movq %%gs:%c[ugs_base], %0"
	    : "=r"(val)
	    : [ugs_base]"i"(offsetof(struct entry_percpu, ugs_base))
	    : "memory");

	return val;
}

static inline void entry_set_ugs_base(uint64_t val)
{
	asm("movq %0, %%gs:%c[ugs_base]"
	    : /* no outputs */
	    : "r"(val), [ugs_base]"i"(offsetof(struct entry_percpu, ugs_base))
	    : "memory");
}

static inline void entry_set_flag_mask(uint64_t val)
{
	asm("orq %0, %%gs:%c[flags]"
	    : /* no outputs */
	    : "r"(val), [flags]"i"(offsetof(struct entry_percpu, flags))
	    : "memory", "cc");
}

static inline void entry_clear_flag_mask(uint64_t val)
{
	asm("andq %0, %%gs:%c[flags]"
	    : /* no outputs */
	    : "r"(~(val)), [flags]"i"(offsetof(struct entry_percpu, flags))
	    : "memory", "cc");
}

static inline bool entry_test_flag_mask(uint64_t val)
{
	asm goto("testq %0, %%gs:%c[flags]\n\t"
		 "jz %l[no_match]\n\t"
		 : /* no outputs */
		 : "r"(val), [flags]"i"(offsetof(struct entry_percpu, flags))
		 : "memory", "cc"
		 : no_match);

	return true;

no_match:
	return false;
}
