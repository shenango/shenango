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

tbench_src = tbench.cc
tbench_obj = $(tbench_src:.cc=.o)

tbench_linux_src = tbench_linux.cc
tbench_linux_obj = $(tbench_linux_src:.cc=.o)

# must be first
all: tbench tbench_linux

tbench: $(tbench_obj)
	$(LD) -o $@ $(LDFLAGS) $(tbench_obj) $(CXXPATH)/librt++.a \
	$(BASEPATH)/libruntime.a $(BASEPATH)/libnet.a $(BASEPATH)/libbase.a \
	-lpthread

tbench_linux: $(tbench_linux_obj)
	$(LD) -o $@ $(LDFLAGS) $(tbench_linux_obj) -lpthread

# general build rules for all targets
src = $(tbench_src) $(tbench_linux_src)
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
	rm -f $(obj) $(dep) tbench tbench_linux