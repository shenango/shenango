/*
 * sysfs.h - utilities for accessing sysfs
 */

#pragma once

#include <base/types.h>

#define SYSFS_PCI_PATH		"/sys/bus/pci/devices"
#define SYSFS_CPU_TOPOLOGY_PATH	"/sys/devices/system/cpu/cpu%d/topology"
#define SYSFS_NODE_PATH		"/sys/devices/system/node/node%d"

extern int sysfs_parse_val(const char *path, uint64_t *val_out);
extern int sysfs_parse_bitlist(const char *path, unsigned long *bits,
			       int nbits);
