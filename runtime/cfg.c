/*
 * cfg.c - configuration file support
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include <base/stddef.h>
#include <base/bitmap.h>
#include <base/log.h>
#include <base/cpu.h>

#include "defs.h"


/*
 * Configuration Options
 */

static int str_to_ip(const char *str, uint32_t *addr)
{
	uint8_t a, b, c, d;
	if(sscanf(str, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) != 4) {
		return -EINVAL;
	}

	*addr = MAKE_IP_ADDR(a, b, c, d);
	return 0;
}

static int str_to_long(const char *str, long *val)
{
	char *endptr;

	*val = strtol(str, &endptr, 10);
	if (endptr == str || (*endptr != '\0' && *endptr != '\n') ||
	    ((*val == LONG_MIN || *val == LONG_MAX) && errno == ERANGE))
		return -EINVAL;
	return 0;
}

static int parse_host_ip(const char *name, const char *val)
{
	uint32_t *addr;
	int ret;

	if (!strcmp(name, "host_addr"))
		addr = &netcfg.addr;
	else if (!strcmp(name, "host_netmask"))
		addr = &netcfg.netmask;
	else if (!strcmp(name, "host_gateway"))
		addr = &netcfg.gateway;
	else
		return -EINVAL;

	if (!val)
		return -EINVAL;

	ret = str_to_ip(val, addr);
	if (ret)
		return ret;

	if (!strcmp(name, "host_netmask") &&
	    (!*addr || ((~*addr + 1) & ~*addr))) {
		log_err("invalid netmask");
		return -EINVAL;
	}

	if (*addr >> 24 == 127) {
		log_err("IP address can't be local subnet");
		return -EINVAL;
	}

	return 0;
}

static int parse_runtime_kthreads(const char *name, const char *val)
{
	long tmp;
	int ret;

	ret = str_to_long(val, &tmp);
	if (ret)
		return ret;

	if (tmp < 1 || tmp > cpu_count - 1) {
		log_err("invalid number of kthreads requested, '%ld'", tmp);
		log_err("must be > 0 and < %d (number of CPUs)", cpu_count);
		return -EINVAL;
	}

	maxks = tmp;
	return 0;
}

static int parse_runtime_spinning_kthreads(const char *name, const char *val)
{
	long tmp;
	int ret;

	ret = str_to_long(val, &tmp);
	if (ret)
		return ret;

	if (tmp < 0) {
		log_err("invalid number of spinning kthreads requests, '%ld', "
			"must be > 0", tmp);
		return -EINVAL;
	}

	spinks = tmp;
	return 0;
}

static int parse_runtime_guaranteed_kthreads(const char *name, const char *val)
{
	long tmp;
	int ret;

	ret = str_to_long(val, &tmp);
	if (ret)
		return ret;

	if (tmp < 1 || tmp > cpu_count - 1) {
		log_err("invalid number of guaranteed kthreads requested, '%ld'", tmp);
		log_err("must be > 0 and < %d (number of CPUs)", cpu_count);
		return -EINVAL;
	}

	guaranteedks = tmp;
	return 0;
}

static int parse_mac_address(const char *name, const char *val)
{
	int i;
	struct eth_addr mac;

	static const char *fmts[] = {
		"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		"%hhx-%hhx-%hhx-%hhx-%hhx-%hhx",
		"%hhx%hhx%hhx%hhx%hhx%hhx"
	};

	for (i = 0; i < ARRAY_SIZE(fmts); i++) {
		if (sscanf(val, fmts[i], &mac.addr[0], &mac.addr[1],
			   &mac.addr[2], &mac.addr[3], &mac.addr[4],
			   &mac.addr[5]) == 6) {
			if (mac.addr[0] & ETH_ADDR_GROUP ||
			    !(mac.addr[0] & ETH_ADDR_LOCAL_ADMIN)) {
				log_err("Invalid mac address");
				return -EINVAL;
			}
			netcfg.mac = mac;
			return 0;
		}
	}

	log_err("Could not parse mac address");
	return -EINVAL;
}


/*
 * Parsing Infrastructure
 */

typedef int (*cfg_fn_t)(const char *name, const char *val);

struct cfg_handler {
	const char	*name;
	cfg_fn_t	fn;
	bool		required;
};

static const struct cfg_handler cfg_handlers[] = {
	{ "host_addr", parse_host_ip, true },
	{ "host_netmask", parse_host_ip, true },
	{ "host_gateway", parse_host_ip, true },
	{ "host_mac", parse_mac_address, false },
	{ "runtime_kthreads", parse_runtime_kthreads, true },
	{ "runtime_spinning_kthreads", parse_runtime_spinning_kthreads, false },
	{ "runtime_guaranteed_kthreads", parse_runtime_guaranteed_kthreads,
			false },
};

/**
 * cfg_load - loads the configuration file
 * @path: a path to the configuration file
 *
 * Returns 0 if successful, otherwise fail.
 */
int cfg_load(const char *path)
{
	FILE *f;
	char buf[BUFSIZ];
	DEFINE_BITMAP(parsed, ARRAY_SIZE(cfg_handlers));
	const char *name, *val;
	int i, ret = 0, line = 0;

	bitmap_init(parsed, ARRAY_SIZE(cfg_handlers), 0);

	log_info("loading configuration from '%s'", path);

	f = fopen(path, "r");
	if (!f)
		return -errno;

	while (fgets(buf, sizeof(buf), f)) {
		if (buf[0] == '#' || buf[0] == '\n') {
			line++;
			continue;
		}
		name = strtok(buf, " ");
		if (!name)
			break;
		val = strtok(NULL, " ");

		for (i = 0; i < ARRAY_SIZE(cfg_handlers); i++) {
			const struct cfg_handler *h = &cfg_handlers[i];
			if (!strncmp(name, h->name, BUFSIZ)) {
				ret = h->fn(name, val);
				if (ret) {
					log_err("bad config option on line %d",
						line);
					goto out;
				}
				bitmap_set(parsed, i);
				break;
			}
		}

		line++;
	}

	for (i = 0; i < ARRAY_SIZE(cfg_handlers); i++) {
		const struct cfg_handler *h = &cfg_handlers[i];
		if (h->required && !bitmap_test(parsed, i)) {
			log_err("missing required config option '%s'", h->name);
			ret = -EINVAL;
			goto out;
		}
	}

	if (guaranteedks > maxks) {
		log_err("invalid number of guaranteed kthreads requested, '%d'",
				guaranteedks);
		log_err("must be <= %d (number of kthreads)", maxks);
		ret = -EINVAL;
		goto out;
	}

out:
	fclose(f);
	return ret;
}
