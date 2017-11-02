/*
 * main.c - initialization for the iokernel
 */

#include <base/init.h>
#include <base/log.h>

#include "defs.h"

int main(int argc, char *argv[])
{
	int ret;

	ret = base_init();
	if (ret) {
		log_err("base_init() failed, ret = %d", ret);
		return ret;
	}

	ret = control_init();
	if (ret) {
		log_err("control_init() failed, ret = %d", ret);
		return ret;
	}

	while (1) {}
	return 0;
}
