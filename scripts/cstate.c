#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int pm_qos_fd = -1;

void set_latency_target(int32_t target_us)
{
	ssize_t ret;

	if (pm_qos_fd >= 0)
		return;
	pm_qos_fd = open("/dev/cpu_dma_latency", O_RDWR);
	if (pm_qos_fd < 0) {
		fprintf(stderr, "Failed to open PM QOS file: %s\n",
			strerror(errno));
		exit(errno);
	}

	ret = write(pm_qos_fd, &target_us, sizeof(target_us));
	if (ret < 0) {
		fprintf(stderr, "Fail to set QOS target\n");
		exit(errno);
	}
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		printf("usage: [maximum c-state latency in microseconds]\n");
		exit(1);
	}

	set_latency_target(atoi(argv[1]));
	while (1)
		sleep(10);
	return 0;
}
