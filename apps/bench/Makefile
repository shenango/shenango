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

tbench_linux_src = tbench_linux.cc
tbench_linux_obj = $(tbench_linux_src:.cc=.o)

callibrate_src = callibrate.cc
callibrate_obj = $(callibrate_src:.cc=.o)

stress_src = stress.cc
stress_obj = $(stress_src:.cc=.o)

efficiency_src = efficiency.cc
efficiency_obj = $(efficiency_src:.cc=.o)

# must be first
all: tbench tbench_linux callibrate stress efficiency

tbench: $(tbench_obj)
	$(LD) -o $@ $(LDFLAGS) $(tbench_obj) $(CXXPATH)/librt++.a \
	$(BASEPATH)/libruntime.a $(BASEPATH)/libnet.a $(BASEPATH)/libbase.a \
	-lpthread

tbench_linux: $(tbench_linux_obj)
	$(LD) -o $@ $(LDFLAGS) $(tbench_linux_obj) -lpthread

callibrate: $(fake_worker_obj) $(callibrate_obj)
	$(LD) -o $@ $(LDFLAGS) $(fake_worker_obj) $(callibrate_obj) -lpthread

stress: $(fake_worker_obj) $(stress_obj)
	$(LD) -o $@ $(LDFLAGS) $(fake_worker_obj) $(stress_obj) \
        $(CXXPATH)/librt++.a $(BASEPATH)/libruntime.a $(BASEPATH)/libnet.a \
        $(BASEPATH)/libbase.a -lpthread

efficiency: $(fake_worker_obj) $(efficiency_obj)
	$(LD) -o $@ $(LDFLAGS) $(fake_worker_obj) $(efficiency_obj) \
        $(CXXPATH)/librt++.a $(BASEPATH)/libruntime.a $(BASEPATH)/libnet.a \
        $(BASEPATH)/libbase.a -lpthread

# general build rules for all targets
src = $(fake_worker_src) $(tbench_src) $(tbench_linux_src) $(callibrate_src)
src += $(stress_src) $(efficiency_src)
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
	rm -f $(obj) $(dep) tbench tbench_linux callibrate stress efficiency
