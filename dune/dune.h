/**
 * dune.h - public header for Dune support
 */

#pragma once

#include <base/types.h>
#include <asm/ioctl.h>

/*
 * IOCTL interface
 */

/* FIXME: this must be reserved in miscdevice.h */
#define DUNE_MINOR       233

#define DUNE_ENTER	_IOR(DUNE_MINOR, 0x01, struct dune_config)
#define DUNE_GET_SYSCALL _IO(DUNE_MINOR, 0x02)
#define DUNE_GET_LAYOUT	_IOW(DUNE_MINOR, 0x03, struct dune_layout)

#define DUNE_SIGNAL_INTR_BASE 200

struct dune_config {
	uintptr_t rip;
	uintptr_t rsp;
	uintptr_t cr3;
	long ret;
} __attribute__((packed));

extern int __dune_enter(int fd, struct dune_config *cfg);
extern int __dune_ret(void);

struct dune_layout {
	uintptr_t phys_limit;
	uintptr_t base_map;
	uintptr_t base_stack;
} __attribute__((packed));

#define GPA_STACK_SIZE	((unsigned long)1 << 28) /* 256 megabytes */
#define GPA_MAP_SIZE	(((unsigned long)1 << 32) - GPA_STACK_SIZE) /* 3.75 gigabytes */

static inline physaddr_t gpa_stack_base(const struct dune_layout *layout)
{
	return layout->phys_limit - GPA_STACK_SIZE;
}

static inline physaddr_t gpa_map_base(const struct dune_layout *layout)
{
	return layout->phys_limit - GPA_STACK_SIZE - GPA_MAP_SIZE;
}

