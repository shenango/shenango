DPDK_PATH = dpdk
INC     = -I./inc -I$(DPDK_PATH)/build/include
CFLAGS  = -g -Wall -std=gnu11 -D_GNU_SOURCE $(INC) -mssse3
LDFLAGS = -T base/base.ld
LD	= gcc
CC	= gcc
AR	= ar
SPARSE	= sparse

CHECKFLAGS = -D__CHECKER__ -Waddress-space

ifneq ($(DEBUG),)
CFLAGS += -DDEBUG -DCCAN_LIST_DEBUG -rdynamic -O0 -ggdb
LDFLAGS += -rdynamic
else
CFLAGS += -DNDEBUG -O3
endif

# handy for debugging
print-%  : ; @echo $* = $($*)

# libbase.a - the base library
base_src = $(wildcard base/*.c)
base_obj = $(base_src:.c=.o)

# libdune.a - the dune library
dune_src = $(wildcard dune/*.c)
dune_asm = $(wildcard dune/*.S)
dune_obj = $(dune_src:.c=.o) $(dune_asm:.S=.o)

#libnet.a - a packet/networking utility library
net_src = $(wildcard net/*.c) $(wildcard net/ixgbe/*.c)
net_obj = $(net_src:.c=.o)

# iokernel - a soft-NIC service
iokernel_src = $(wildcard iokernel/*.c)
iokernel_obj = $(iokernel_src:.c=.o)

# runtime - a user-level threading and networking library
runtime_src = $(wildcard runtime/*.c)
runtime_asm = $(wildcard runtime/*.S)
runtime_obj = $(runtime_src:.c=.o) $(runtime_asm:.S=.o)

# test cases
test_src = $(wildcard tests/*.c)
test_obj = $(test_src:.c=.o)
test_targets = $(basename $(test_src))

# dpdk libs
DPDK_LIBS= -L$(DPDK_PATH)/build/lib
DPDK_LIBS += -Wl,-whole-archive -lrte_pmd_e1000 -Wl,-no-whole-archive
DPDK_LIBS += -Wl,-whole-archive -lrte_pmd_ixgbe -Wl,-no-whole-archive
DPDK_LIBS += -Wl,-whole-archive -lrte_mempool_ring -Wl,-no-whole-archive
DPDK_LIBS += -ldpdk
DPDK_LIBS += -lrte_eal
DPDK_LIBS += -lrte_ethdev
DPDK_LIBS += -lrte_hash
DPDK_LIBS += -lrte_mbuf
DPDK_LIBS += -lrte_mempool
DPDK_LIBS += -lrte_mempool
DPDK_LIBS += -lrte_mempool_stack
DPDK_LIBS += -lrte_ring

# must be first
all: libbase.a libdune.a libnet.a libruntime.a iokerneld $(test_targets)

libbase.a: $(base_obj)
	$(AR) rcs $@ $^

libdune.a: $(dune_obj)
	$(AR) rcs $@ $^

libnet.a: $(net_obj)
	$(AR) rcs $@ $^

libruntime.a: $(runtime_obj)
	$(AR) rcs $@ $^

iokerneld: $(iokernel_obj) libbase.a libnet.a base/base.ld
	$(LD) $(LDFLAGS) -o $@ $(iokernel_obj) libbase.a libnet.a $(DPDK_LIBS) \
	-lpthread -lnuma -ldl

$(test_targets): $(test_obj) libbase.a libruntime.a base/base.ld
	$(LD) $(LDFLAGS) -o $@ $@.o libbase.a libruntime.a -lpthread

# general build rules for all targets
src = $(base_src) $(dune_src) $(net_src) $(runtime_src) $(iokernel_src) $(test_src)
asm = $(dune_asm) $(runtime_asm)
obj = $(src:.c=.o) $(asm:.S=.o)
dep = $(obj:.o=.d)

ifneq ($(MAKECMDGOALS),clean)
-include $(dep)   # include all dep files in the makefile
endif

# rule to generate a dep file by using the C preprocessor
# (see man cpp for details on the -MM and -MT options)
%.d: %.c
	@$(CC) $(CFLAGS) $< -MM -MT $(@:.d=.o) >$@
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
%.d: %.S
	@$(CC) $(CFLAGS) $< -MM -MT $(@:.d=.o) >$@
%.o: %.S
	$(CC) $(CFLAGS) -c $< -o $@

# prints sparse checker tool output
sparse: $(src)
	$(foreach f,$^,$(SPARSE) $(filter-out -std=gnu11, $(CFLAGS)) $(CHECKFLAGS) $(f);)

.PHONY: clean
clean:
	rm -f $(obj) $(dep) libbase.a libdune.a libnet.a libruntime.a \
	iokerneld $(test_targets)
