/*
 * log.h - the logging service
 */

#pragma once

#include <stdlib.h>

#include <base/stddef.h>
#include <base/time.h>
#include <base/init.h>

extern void logk(int level, const char *fmt, ...)
	__attribute__((__format__ (__printf__, 2, 3)));
extern void logk_backtrace(void);

/* forces format checking */
#define no_logk(level, fmt, ...) \
	do {if (0) logk(level, fmt, ##__VA_ARGS__);} while (0)

extern int max_loglevel;

enum {
	LOG_EMERG	= 0, /* emergency */
	LOG_CRIT	= 1, /* critical */
	LOG_ERR	   	= 2, /* error */
	LOG_WARN	= 3, /* warning */
	LOG_NOTICE	= 4, /* significant normal condition */
	LOG_INFO	= 5, /* informational */
	LOG_DEBUG	= 6, /* debug */
};

#define log_emerg(fmt, ...) logk(LOG_EMERG, fmt, ##__VA_ARGS__)
#define log_crit(fmt, ...) logk(LOG_CRIT, fmt, ##__VA_ARGS__)
#define log_err(fmt, ...) logk(LOG_ERR, fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...) logk(LOG_WARN, fmt, ##__VA_ARGS__)
#define log_notice(fmt, ...) logk(LOG_NOTICE, fmt, ##__VA_ARGS__)
#define log_info(fmt, ...) logk(LOG_INFO, fmt, ##__VA_ARGS__)
#ifdef DEBUG
#define log_debug(fmt, ...) logk(LOG_DEBUG, fmt, ##__VA_ARGS__)
#else /* DEBUG */
#define log_debug(fmt, ...) no_logk(LOG_DEBUG, fmt, ##__VA_ARGS__)
#endif /* DEBUG */

#define log_once(level, fmt, ...)			\
({							\
	static bool __once;				\
	if (unlikely(!__once)) {			\
		__once = true;				\
		logk(level, fmt, ##__VA_ARGS__);	\
	}						\
})

#define log_emerg_once(fmt, ...) log_once(LOG_EMERG, fmt, ##__VA_ARGS__)
#define log_crit_once(fmt, ...) log_once(LOG_CRIT, fmt, ##__VA_ARGS__)
#define log_err_once(fmt, ...) log_once(LOG_ERR, fmt, ##__VA_ARGS__)
#define log_warn_once(fmt, ...) log_once(LOG_WARN, fmt, ##__VA_ARGS__)
#define log_notice_once(fmt, ...) log_once(LOG_NOTICE, fmt, ##__VA_ARGS__)
#define log_info_once(fmt, ...) log_once(LOG_INFO, fmt, ##__VA_ARGS__)
#ifdef DEBUG
#define log_debug_once(fmt, ...) log_once(LOG_DEBUG, fmt, ##__VA_ARGS__)
#else /* DEBUG */
#define log_debug_once(fmt, ...) no_logk(LOG_DEBUG, fmt, ##__VA_ARGS__)
#endif /* DEBUG */

#define log_first_n(level, num, fmt, ...)		\
({							\
	static int __n = (num);					\
	if (__n > 0) {							\
		__n--;								\
		logk(level, fmt, ##__VA_ARGS__);	\
	}										\
})

#define log_emerg_first_n(num, fmt, ...) \
	log_first_n(LOG_EMERG, num, fmt, ##__VA_ARGS__)
#define log_crit_first_n(num, fmt, ...) \
	log_first_n(LOG_CRIT, num, fmt, ##__VA_ARGS__)
#define log_err_first_n(num, fmt, ...) \
	log_first_n(LOG_ERR, num, fmt, ##__VA_ARGS__)
#define log_warn_first_n(num, fmt, ...) \
	log_first_n(LOG_WARN, num, fmt, ##__VA_ARGS__)
#define log_notice_first_n(num, fmt, ...) \
	log_first_n(LOG_NOTICE, num, fmt, ##__VA_ARGS__)
#define log_info_first_n(num, fmt, ...) \
	log_first_n(LOG_INFO, num, fmt, ##__VA_ARGS__)
#ifdef DEBUG
#define log_debug_first_n(num, fmt, ...) \
	log_first_n(LOG_DEBUG, num, fmt, ##__VA_ARGS__)
#else /* DEBUG */
#define log_debug_first_n(num, fmt, ...) \
	no_logk(LOG_DEBUG, fmt, ##__VA_ARGS__)
#endif /* DEBUG */

#define log_ratelimited(level, fmt, ...)		\
({							\
	static uint64_t __last_us = 0;			\
	static uint64_t __suppressed = 0;		\
	uint64_t __cur_us = microtime();		\
	if (__cur_us - __last_us >= ONE_SECOND) {	\
		if (__suppressed) {			\
			logk(level, "%s:%d %s() suppressed %ld times", \
			     __FILE__, __LINE__, __func__, __suppressed); \
			__suppressed = 0;		\
		}					\
		logk(level, fmt, ##__VA_ARGS__);	\
		__last_us = __cur_us;			\
	} else						\
		__suppressed++;				\
})

#define log_emerg_ratelimited(fmt, ...) \
	log_ratelimited(LOG_EMERG, fmt, ##__VA_ARGS__)
#define log_crit_ratelimited(fmt, ...) \
	log_ratelimited(LOG_CRIT, fmt, ##__VA_ARGS__)
#define log_err_ratelimited(fmt, ...) \
	log_ratelimited(LOG_ERR, fmt, ##__VA_ARGS__)
#define log_warn_ratelimited(fmt, ...) \
	log_ratelimited(LOG_WARN, fmt, ##__VA_ARGS__)
#define log_notice_ratelimited(fmt, ...) \
	log_ratelimited(LOG_NOTICE, fmt, ##__VA_ARGS__)
#define log_info_ratelimited(fmt, ...) \
	log_ratelimited(LOG_INFO, fmt, ##__VA_ARGS__)
#ifdef DEBUG
#define log_debug_ratelimited(fmt, ...) \
	log_ratelimited(LOG_DEBUG, fmt, ##__VA_ARGS__)
#else /* DEBUG */
#define log_debug_ratelimited(fmt, ...) \
	no_logk(LOG_DEBUG, fmt, ##__VA_ARGS__)
#endif /* DEBUG */

#define panic(fmt, ...)					\
	do {logk(LOG_EMERG, fmt, ##__VA_ARGS__);	\
	    init_shutdown(EXIT_FAILURE);} while (0)
