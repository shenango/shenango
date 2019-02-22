# Makefile for benchmarks

BASEPATH = ../..
CXXPATH = ../../bindings/cc
INC     = -I../../inc -I../../bindings/cc -I./
CXXFLAGS  = -g -Wall -std=gnu++11 -D_GNU_SOURCE $(INC) -mssse3
LDFLAGS = -T../../base/base.ld -no-pie

LD	= g++
CC	= g++
AR	= ar

ifneq ($(DEBUG),)
CXXFLAGS += -DDEBUG -DCCAN_LIST_DEBUG -rdynamic -O0 -ggdb
LDFLAGS += -rdynamic
else
CXXFLAGS += -DNDEBUG -O3
endif

# handy for debugging
print-%  : ; @echo $* = $($*)

fake_worker_src = fake_worker.cc
fake_worker_obj = $(fake_worker_src:.cc=.o)

tbench_src = tbench.cc
tbench_obj = $(tbench_src:.cc=.o)

callibrate_src = callibrate.cc
callibrate_obj = $(callibrate_src:.cc=.o)

stress_src = stress.cc
stress_obj = $(stress_src:.cc=.o)

stress_linux_src = stress_linux.cc
stress_linux_obj = $(stress_linux_src:.cc=.o)

efficiency_src = efficiency.cc
efficiency_obj = $(efficiency_src:.cc=.o)

efficiency_linux_src = efficiency_linux.cc
efficiency_linux_obj = $(efficiency_linux_src:.cc=.o)

netbench_src = netbench.cc
netbench_obj = $(netbench_src:.cc=.o)

netbench2_src = netbench2.cc
netbench2_obj = $(netbench2_src:.cc=.o)

netbench_udp_src = netbench_udp.cc
netbench_udp_obj = $(netbench_udp_src:.cc=.o)

netbench_linux_src = netbench_linux.cc
netbench_linux_obj = $(netbench_linux_src:.cc=.o)

netperf_src = netperf.cc
netperf_obj = $(netperf_src:.cc=.o)

linux_mech_bench_src = linux_mech_bench.cc
linux_mech_bench_obj = $(linux_mech_bench_src:.cc=.o)

librt_libs = $(CXXPATH)/librt++.a $(BASEPATH)/libruntime.a $(BASEPATH)/libnet.a $(BASEPATH)/libbase.a

# must be first
all: tbench callibrate stress efficiency efficiency_linux \
     netbench netbench2 netbench_udp netbench_linux netperf linux_mech_bench \
     stress_linux

tbench: $(tbench_obj) $(librt_libs)
	$(LD) -o $@ $(LDFLAGS) $(tbench_obj) $(librt_libs) -lpthread

callibrate: $(fake_worker_obj) $(callibrate_obj)
	$(LD) -o $@ $(LDFLAGS) $(fake_worker_obj) $(callibrate_obj) -lpthread

stress: $(fake_worker_obj) $(stress_obj) $(librt_libs)
	$(LD) -o $@ $(LDFLAGS) $(fake_worker_obj) $(stress_obj) $(librt_libs) -lpthread

stress_linux: $(fake_worker_obj) $(stress_linux_obj)
	$(LD) -o $@ $(LDFLAGS) $(fake_worker_obj) $(stress_linux_obj) \
	-lpthread

efficiency: $(fake_worker_obj) $(efficiency_obj) $(librt_libs)
	$(LD) -o $@ $(LDFLAGS) $(fake_worker_obj) $(efficiency_obj) $(librt_libs) -lpthread

efficiency_linux: $(fake_worker_obj) $(efficiency_linux_obj)
	$(LD) -o $@ $(LDFLAGS) $(fake_worker_obj) $(efficiency_linux_obj) \
	-lpthread

netbench: $(netbench_obj) $(fake_worker_obj) $(librt_libs)
	$(LD) -o $@ $(LDFLAGS) $(fake_worker_obj) $(netbench_obj) $(librt_libs) -lpthread

netbench2: $(netbench2_obj) $(fake_worker_obj) $(librt_libs)
	$(LD) -o $@ $(LDFLAGS) $(fake_worker_obj) $(netbench2_obj) $(librt_libs) -lpthread

netbench_udp: $(netbench_udp_obj) $(fake_worker_obj) $(librt_libs)
	$(LD) -o $@ $(LDFLAGS) $(fake_worker_obj) $(netbench_udp_obj) $(librt_libs) -lpthread

netbench_linux: $(netbench_linux_obj) $(fake_worker_obj)
	$(LD) -o $@ $(LDFLAGS) $(fake_worker_obj) $(netbench_linux_obj) -lpthread

netperf: $(netperf_obj) $(librt_libs)
	$(LD) -o $@ $(LDFLAGS) $(netperf_obj) $(librt_libs) -lpthread

linux_mech_bench: $(linux_mech_bench_obj) $(librt_libs)
	$(LD) -o $@ $(LDFLAGS) $(linux_mech_bench_obj) $(librt_libs) -lpthread

# general build rules for all targets
src = $(fake_worker_src) $(tbench_src) $(callibrate_src)
src += $(stress_src) $(efficiency_src) $(efficiency_linux_src) $(netbench_src)
src += $(netbench2_src) $(netbench_udp_src) $(netbench_linux_src) $(netperf_src)
src += $(linux_mech_bench_src)
obj = $(src:.cc=.o)
dep = $(obj:.o=.d)

ifneq ($(MAKECMDGOALS),clean)
-include $(dep)   # include all dep files in the makefile
endif

# rule to generate a dep file by using the C preprocessor
# (see man cpp for details on the -MM and -MT options)
%.d: %.cc
	@$(CC) $(CXXFLAGS) $< -MM -MT $(@:.d=.o) >$@
%.o: %.cc
	$(CC) $(CXXFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(obj) $(dep) tbench callibrate stress efficiency \
	efficiency_linux netbench netbench2 netbench_udp netbench_linux \
	netperf linux_mech_bench stress_linux
