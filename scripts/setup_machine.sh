#!/bin/bash

# run with sudo
echo 1 > /proc/sys/kernel/shm_rmid_forced
sysctl -w kernel.shmmax=18446744073692774399
