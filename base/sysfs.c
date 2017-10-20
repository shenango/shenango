/*
 * sysfs.c - utilities for accessing sysfs
 */

#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>

#include <base/stddef.h>
#include <base/sysfs.h>
#include <base/bitmap.h>

/**
 * sysfs_parse_val - parses a 64-bit unsigned value from a sysfs file
 * @path: the sysfs file path
 * @val_out: a pointer to store the result
 *
 * Returns 0 if successful, otherwise fail.
 */
int sysfs_parse_val(const char *path, uint64_t *val_out)
{
	FILE *f;
	char buf[BUFSIZ];
	char *end;
	int ret = 0;
	uint64_t val;

	f = fopen(path, "r");
	if (!f)
		return -EIO;

	if (!fgets(buf, sizeof(buf), f)) {
		ret = -EIO;
		goto out;
	}

	val = strtoull(buf, &end, 0);
	if (val == ULLONG_MAX) {
		ret = -errno;
		goto out;
	}
	if (end == buf || *end != '\n') {
		ret = -EINVAL;
		goto out;
	}
	*val_out = val;

out:
	fclose(f);
	return ret;
}

/**
 * sysfs_parse_bitlist - parses a bitlist value from a sysfs file
 * @path: the sysfs file path
 * @bits: the bitmap to store the result
 * @nbits: the number of bits in the bitmap
 *
 * Returns 0 if successful, otherwise fail.
 */
int sysfs_parse_bitlist(const char *path, unsigned long *bits, int nbits)
{
	FILE *f;
	char buf[BUFSIZ];
	char *pos, *end;
	int ret = 0, bit_start, bit_end;
	uint64_t val;

	f = fopen(path, "r");
	if (!f)
		return -EIO;

	if (!fgets(buf, sizeof(buf), f)) {
		ret = -EIO;
		goto out;
	}

	bitmap_init(bits, nbits, false);
	pos = &buf[0];
	while (*pos != '\0' && *pos != '\n') {
		if (*pos == ',') {
			pos++;
			continue;
		}

		val = strtoull(pos, &end, 0);
		if (val == ULLONG_MAX) {
			ret = -errno;
			goto out;
		}
		if (end == pos) {
			ret = -EINVAL;
			goto out;
		}
		if (val > INT_MAX) {
			ret = -ERANGE;
			goto out;
		}

		bit_start = (int)val;
		pos = end;
		if (*pos == '-') {
			pos++;

			val = strtoull(pos, &end, 0);
			if (val == ULLONG_MAX) {
				ret = -errno;
				goto out;
			}
			if (end == pos) {
				ret = -EINVAL;
				goto out;
			}
			if (val > INT_MAX) {
				ret = -ERANGE;
				goto out;
			}

			bit_end = (int)val;
			pos = end;
		} else {
			bit_end = bit_start;
		}

		if (bit_end < bit_start) {
			ret = EINVAL;
			goto out;
		}
		if (bit_end >= nbits) {
			ret = -ERANGE;
			goto out;
		}

		for (; bit_start <= bit_end; bit_start++)
			bitmap_set(bits, bit_start);
	}

out:
	fclose(f);
	return ret;
}
