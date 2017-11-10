/*
 * main.c - initialization for the iokernel
 */

#include <base/init.h>
#include <base/log.h>

#include "defs.h"

int main(int argc, char *argv[])
{
	int ret;
	int port = 0;

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

	ret = dpdk_init(port);
	if (ret) {
		log_err("dpdk_init() failed, ret = %d", ret);
		return ret;
	}

	dpdk_run(port);
	return 0;
}
