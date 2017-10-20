/*
 * init_internal.h - internal base library initialization routines
 */

#pragma once

/* internal base library initializers */
extern int cpu_init(void);
extern int time_init(void);
extern int page_init(void);
extern int slab_init(void);
extern int smalloc_init(void);

/* internal base library per-thread initializers */
extern int page_init_thread(void);
extern int smalloc_init_thread(void);
