/*
 * procmap.h - parses linux process map information
 */

#pragma once

#include <base/stddef.h>

struct procmap_entry {
	uintptr_t	begin;
	uintptr_t	end;
	uint64_t	offset;
	bool		r; // Readable
	bool		w; // Writable
	bool		x; // Executable
	bool		p; // Private (or shared)
	char		*path;
	int		type;
};

#define PROCMAP_TYPE_UNKNOWN	0x00
#define PROCMAP_TYPE_FILE	0x01
#define PROCMAP_TYPE_ANONYMOUS	0x02
#define PROCMAP_TYPE_HEAP	0x03
#define PROCMAP_TYPE_STACK	0x04
#define PROCMAP_TYPE_VSYSCALL	0x05
#define PROCMAP_TYPE_VDSO	0x06
#define PROCMAP_TYPE_VVAR	0x07

typedef int (*procmap_cb_t)(const struct procmap_entry *, unsigned long data);

extern int procmap_iterate(procmap_cb_t cb, unsigned long data);
extern void procmap_dump(void);
