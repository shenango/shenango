/*
 * limits.h - maximum limits for different resources
 */

#pragma once

#define NCPU		256	/* max number of cpus */
#define NTHREAD		(NCPU - 1)	/* max number ofk threads */
#define NNUMA		4	/* max number of numa zones */
#define NSTAT		1024	/* max number of stat counters */
