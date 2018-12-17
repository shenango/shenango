#!/bin/bash

# run with sudo
sysctl -w kernel.shm_rmid_forced=1
sysctl -w kernel.shmmax=18446744073692774399
sysctl -w vm.hugetlb_shm_group=27
sysctl -w vm.max_map_count=16777216
sysctl -w net.core.somaxconn=3072

echo 8192 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages

for n in /sys/devices/system/node/node[1-9]; do
	echo 0 > $n/hugepages/hugepages-2048kB/nr_hugepages
done


