# Threading Benchmarks

First build Shenango and then build the benchmarks in this directory
with `make clean && make`. Run the main Shenango threading benchmarks
as follows (benchmarks will use a single runtime core).

In shenango directory:
```
sudo ./iokerneld
```

In this directory:
```
./tbench tbench.config
```