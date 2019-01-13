# Latency Benchmarks

First build DPDK (without driver modifications), then build
dpdk_netperf in this directory with `make clean && make`. To run the
benchmark:

On the server (IP 192.168.1.2):
```
sudo ./build/dpdk_netperf -l2 --socket-mem=128 -- UDP_SERVER 192.168.1.2
```

On the client (IP 192.168.1.3):
```
sudo ./build/dpdk_netperf -l2 --socket-mem=128 -- UDP_CLIENT 192.168.1.3 192.168.1.2 50000 8000 5 32
```
