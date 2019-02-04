# Shenango

Shenango is a system that enables servers in datacenters to
simultaneously provide low tail latency and high CPU efficiency, by
rapidly reallocating cores across applications, at timescales as small
as every 5 microseconds.

## How to Run Shenango

1) Clone the Shenango repository.

```
git clone https://github.com/abelay/shenango
cd shenango
```

2) Setup DPDK and build the IOKernel and Shenango runtime.

```
./dpdk.sh
./scripts/setup_machine.sh
make clean && make
```

To enable debugging, build with `make DEBUG=1`.

3) Setup hugepages. We require at least 64 2MB hugepages. Run the script below
and follow the instructions for NUMA or non-NUMA systems, as appropriate.

```
./dpdk/usertools/dpdk-setup.sh
```

4) Install Rust and build a synthetic client-server application.

```
curl https://sh.rustup.rs -sSf | sh
rustup default nightly
```
```
cd apps/synthetic
cargo clean
cargo update
cargo build --release
```

5) Run the synthetic application with a client and server. The client
sends requests to the server, which performs a specified amount of
fake work (e.g., computing square roots for 10us), before responding.

On the server:
```
sudo ./iokerneld
./apps/synthetic/target/release/synthetic 192.168.1.3:5000 --config server.config --mode spawner-server
```

On the client:
```
sudo ./iokerneld
./apps/synthetic/target/release/synthetic 192.168.1.3:5000 --config client.config --mode runtime-client
```

## Supported Platforms

This code has been tested most thoroughly on Ubuntu 17.10, with kernel
4.14.0. It has been tested with Intel 82599ES 10 Gbit/s NICs and
Mellanox ConnectX-3 Pro 10 Gbit/s NICs. If you use Mellanox NICs, you
should install the Mellanox OFED as described in [DPDK's
documentation](https://doc.dpdk.org/guides/nics/mlx4.html).
