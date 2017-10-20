/*
 * trap.c - x86 exception and interrupt support
 */

#include <base/stddef.h>
#include <base/log.h>
#include <dune/vm.h>
#include <dune/entry.h>
#include <dune/trap.h>
#include <dune/msr.h>

#define STACK_DUMP_DEPTH	16
#define NUM_CODES		20

static const char *trap_codes[NUM_CODES] = {
	"divide error",
	"debug exception",
	"non-maskable interrupt",
	"breakpoint",
	"overflow",
	"bounds check",
	"illegal opcode",
	"dev not available",
	"double fault",
	"reserved",
	"invalid TSS",
	"segment not present",
	"stack exception",
	"general protection fault",
	"page fault",
	"reserved",
	"floating point error",
	"alignment check",
	"machine check",
	"SIMD error",
};

static int safe_peekq(uint64_t *addr, uint64_t *val)
{
	int ret, level;
	ptent_t *pte;

	ret = vm_lookup_pte(kern_pgtbl, addr, &level, &pte);
	if (ret)
		return ret;

	if (!(*pte & PTE_P))
		return -EINVAL;

	if (*pte & PTE_PAGE) {
		uint64_t *direct_ptr = (uint64_t *)((char *)PTE_ADDR(*pte) +
			((off_t)addr & (PGLEVEL_TO_SIZE(level) - 1)));
		*val = *direct_ptr;
	} else {
		*val = *(uint64_t *)addr;
	}

	return 0;
}

static void dump_stack(uintptr_t rsp)
{
	int i;
	uint64_t *sp = (uint64_t *)rsp;

	log_info("dumping stack contents:\n");

	if (rsp & (sizeof(uint64_t) - 1)) {
		log_err("misaligned stack\n");
		return;
	}

	for (i = 0; i < STACK_DUMP_DEPTH; i++) {
		uint64_t val;

		if (!safe_peekq(&sp[i], &val)) {
			log_info("*(RSP+%03d) 0x%016lx\n",
				 (int)(i * sizeof(uint64_t)), val);
		} else {
			log_info("*(RSP+%03d) <unmapped>\n",
				 (int)(i * sizeof(uint64_t)));
			break;
		}
	}
}

void dump_trap_frame(struct env_tf *tf)
{
        log_info("--- Begin Frame Dump ---\n");
        log_info("RIP 0x%016lx\n", tf->rip);
        log_info("CS 0x%02x SS 0x%02x\n", tf->cs, tf->ss);
        log_info("ERR 0x%08x RFLAGS 0x%08lx\n", tf->err, tf->rflags);
        log_info("RAX 0x%016lx RCX 0x%016lx\n", tf->rax, tf->rcx);
        log_info("RDX 0x%016lx RBX 0x%016lx\n", tf->rdx, tf->rbx);
        log_info("RSP 0x%016lx RBP 0x%016lx\n", tf->rsp, tf->rbp);
        log_info("RSI 0x%016lx RDI 0x%016lx\n", tf->rsi, tf->rdi);
        log_info("R8  0x%016lx R9  0x%016lx\n", tf->r8, tf->r9);
        log_info("R10 0x%016lx R11 0x%016lx\n", tf->r10, tf->r11);
        log_info("R12 0x%016lx R13 0x%016lx\n", tf->r12, tf->r13);
        log_info("R14 0x%016lx R15 0x%016lx\n", tf->r14, tf->r15);
	log_info("FS.base 0x%016lx GS.base 0x%016lx\n",
		 getfsbase(), getgsbase());
	dump_stack(tf->rsp);
        log_info("--- End Frame Dump ---\n");
}

static void dump_pgflt(struct env_tf *tf)
{
	uint32_t fec = tf->err;
	uintptr_t fault_addr;

	asm volatile("mov %%cr2, %0" : "=r" (fault_addr));

	log_err("trap: %s page fault at ADDR 0x%016lx (%s, %s%s)\n",
		(fec & FEC_U) ? "user" : "kernel", fault_addr,
		(fec & FEC_P) ? "protection" : "non-present page",
		(fec & FEC_RSV) ? "reserved bit error, " : "",
		(fec & FEC_I) ? "code" : "data");
	if (fault_addr < PGSIZE_4KB)
		log_err("trap: likely NULL pointer exception\n");
}

void trap_handler(int num, struct env_tf *tf)
{
	bool user = ((tf->cs & 0x3) == 0x3);

	if (num == T_PGFLT) {
		dump_pgflt(tf);
	} else {
		log_err("trap: unhandled trap %d (%s) in %s\n", num,
			num < NUM_CODES ? trap_codes[num] : "spurious",
			user ? "user" : "kernel");
	}

	dump_trap_frame(tf);
	init_shutdown(EXIT_FAILURE);
}
