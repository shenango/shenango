#!/bin/bash

# run with sudo
sysctl -w kernel.shm_rmid_forced=1
sysctl -w kernel.shmmax=18446744073692774399
sysctl -w vm.hugetlb_shm_group=27
sysctl -w vm.max_map_count=655300

echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages

for n in /sys/devices/system/node/node[1-9]; do
	echo 0 > $n/hugepages/hugepages-2048kB/nr_hugepages
done


