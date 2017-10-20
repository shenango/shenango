/*
 * entry.c - routines for managing Dune, user-kernel mode transitions,
 *	     and CPU initialization
 */

#include <fcntl.h>
#include <sys/ioctl.h>
#include <asm/prctl.h>

#include <base/stddef.h>
#include <base/page.h>
#include <base/log.h>
#include <base/thread.h>
#include <base/lock.h>

#include <dune/vm.h>
#include <dune/procmap.h>
#include <dune/entry.h>
#include <dune/mmu.h>
#include <dune/trap.h>
#include <dune/fpu.h>
#include <dune/msr.h>

#include "dune.h"

/*
 * kern_pgtbl contains all the mappings necessary to run the kernel.
 * After initialization, it is immutable, and therefore does not
 * require locking.
 */
ptent_t *kern_pgtbl;

/* the per-cpu kernel context stack pointer */
__thread uintptr_t kern_sp;

uintptr_t entry_vdso_base;

static int dune_fd;
static bool linux_has_vvar;

static DEFINE_SPINLOCK(entry_lock);
static struct idtd idt_template[IDT_ENTRIES];
static struct idtd *idt_node[NNUMA];

static uint64_t gdt_template[GDT_ENTRIES] = {
        0,
        0,
        SEG64(SEG_X | SEG_R, 0),
        SEG64(SEG_W, 0),
        0,
        SEG64(SEG_W, 3),
        SEG64(SEG_X | SEG_R, 3),
        0,
        0,
};

static inline void set_idt_addr(struct idtd *id, physaddr_t addr)
{
	id->low    = addr & 0xFFFF;
	id->middle = (addr >> 16) & 0xFFFF;
	id->high   = (addr >> 32) & 0xFFFFFFFF;
}

static void entry_init_idt(void)
{
        int i;

	for (i = 0; i < IDT_ENTRIES; i++) {
		struct idtd *id = &idt_template[i];
		uintptr_t isr = (uintptr_t)&trap_entry_tbl[TRAP_ENTRY_SIZE * i];

		memset(id, 0, sizeof(*id));

		id->selector = GD_KT;
		id->type     = IDTD_P | IDTD_TRAP_GATE;

		switch (i) {
		case T_BRKPT:
			id->type |= IDTD_CPL3;
			/* fallthrough */
		case T_DBLFLT:
		case T_NMI:
		case T_MCHK:
			id->ist = 1;
			break;
		}

		set_idt_addr(id, isr);
	}
}

static int entry_init_layout(struct dune_layout *layout)
{
	int ret = ioctl(dune_fd, DUNE_GET_LAYOUT, layout);
	if (ret)
		return -EIO;

	log_info("entry: dune mem layout\n");
	log_info("\tphys_limit\t0x%016lx\n", layout->phys_limit);
	log_info("\tmap_base\t0x%016lx\n", layout->base_map);
	log_info("\tstack_back\t0x%016lx\n", layout->base_stack);

	return 0;
}

static ptent_t procmap_entry_to_flags(const struct procmap_entry *e)
{
	ptent_t flags = PTE_P | PTE_G;

	if (e->w)
		flags |= PTE_W;
	if (!e->x)
		flags |= PTE_NX;

	return flags;
}

static int entry_procmap_cb(const struct procmap_entry *e, unsigned long data)
{
	struct dune_layout *layout = (struct dune_layout *) data;

	if (e->type == PROCMAP_TYPE_VDSO || e->type == PROCMAP_TYPE_VVAR) {
		off_t off = e->begin - layout->base_stack;
		size_t len = e->end - e->begin;
		ptent_t flags = procmap_entry_to_flags(e);

		if (e->type == PROCMAP_TYPE_VVAR)
			linux_has_vvar = true;
		else
			entry_vdso_base = e->begin;

		if (off + len > GPA_STACK_SIZE)
			panic("entry: dune stack region does not contain vsdo\n");

		if (flags & PTE_W) {
			log_err("entry: can't support writable vdso regions\n");
			return -EINVAL;
		}

		return vm_map_phys(kern_pgtbl, gpa_stack_base(layout) + off,
				   (void *)e->begin, len, PGSIZE_4KB, flags | PTE_U);
	}

	if (e->type == PROCMAP_TYPE_VSYSCALL) {
		return vm_map_copy(kern_pgtbl, vsyscall_page, (void *)e->begin,
				   PGSIZE_4KB, PGSIZE_4KB, PTE_P | PTE_G | PTE_U);
	}

	if (e->type == PROCMAP_TYPE_STACK) {
		off_t off = e->begin - layout->base_stack;
		return vm_map_phys(kern_pgtbl, gpa_stack_base(layout) + off,
				   (void *)e->begin, e->end - e->begin, PGSIZE_4KB,
				   PTE_P | PTE_W | PTE_G | PTE_NX);
	}

	/* ignore entries inside the dune map region */
	if (e->end >= gpa_map_base(layout)) {
		if (e->begin < layout->base_map ||
		    e->end > layout->base_map + GPA_MAP_SIZE) {
			log_err("entry: procmap entry is out of range - "
				"0x%016lx-0x%016lx %c%c%c%c %08lx %s\n",
				e->begin, e->end,
				e->r ? 'R' : '-',
				e->w ? 'W' : '-',
				e->x ? 'X' : '-',
				e->p ? 'P' : 'S',
				e->offset, e->path);

			return -EINVAL;
		}

		return 0;
	}

	/* skip regions mapped by the page allocator */
	if (e->begin >= PAGE_BASE_ADDR && e->end <= PAGE_END_ADDR)
		return 0;

	return vm_map_phys(kern_pgtbl, (physaddr_t)e->begin, (void *)e->begin,
			   e->end - e->begin, PGSIZE_4KB,
			   procmap_entry_to_flags(e));
}

static int entry_setup_oldstyle_vvar(void)
{
	log_info("entry: didn't find [vvar] section, creating one manually\n");

#define VVAR_ADDR 0xffffffffff5ff000UL
	return vm_map_copy(kern_pgtbl, (void *)VVAR_ADDR, (void *)VVAR_ADDR,
			   PGSIZE_4KB, PGSIZE_4KB, PTE_P | PTE_G | PTE_U);
}

static int entry_setup_syscall(void)
{
	int ret;
	uintptr_t lstar, aligned_lstar;
	struct page *pg;
	size_t total_len = (size_t)syscall_enter_end -
			   (size_t)syscall_enter;
	size_t part_len;
	void *buf;

	BUG_ON(total_len > PGSIZE_4KB);

	lstar = ioctl(dune_fd, DUNE_GET_SYSCALL);
	if (lstar == -1)
		return -EIO;

	aligned_lstar = PGADDR_4KB(lstar);

	pg = page_alloc(PGSIZE_4KB);
	if (!pg)
		return -ENOMEM;

	ret = vm_insert_page(kern_pgtbl, (void *)aligned_lstar,
			     pg, PTE_P | PTE_G);
	if (ret)
		return ret;

	part_len = min(total_len, PGSIZE_4KB - PGOFF_4KB(lstar));
	buf = (char *)page_to_addr(pg) + PGOFF_4KB(lstar);
	memcpy(buf, syscall_enter, part_len);
	total_len -= part_len;

	/* did the handler spill over to a second page boundary? */
	if (total_len) {
		pg = page_alloc(PGSIZE_4KB);
		if (!pg)
			return -ENOMEM;

		aligned_lstar += PGSIZE_4KB;
		ret = vm_insert_page(kern_pgtbl, (void *)aligned_lstar,
				     pg, PTE_P | PTE_G);
		if (ret)
			return ret;

		buf = page_to_addr(pg);
		memcpy(buf, &syscall_enter[part_len], total_len);
	}

	return 0;
}

static int entry_init_pgtbl(const struct dune_layout *layout)
{
	int ret;

	kern_pgtbl = vm_create_pt();
	if (!kern_pgtbl)
		return -ENOMEM;

	/* step 1: bulk map the dune map region */
	ret = vm_map_phys(kern_pgtbl, gpa_map_base(layout),
			  (void *)layout->base_map, GPA_MAP_SIZE,
			  PGSIZE_2MB, PTE_P | PTE_W | PTE_G);
	if (ret)
		goto fail;

	/* step 2: identity map the base library page-map region */
	ret = vm_map_phys(kern_pgtbl, (physaddr_t)PAGE_BASE_ADDR,
			  (void *)PAGE_BASE_ADDR, PAGE_END_ADDR - PAGE_BASE_ADDR,
			  PGSIZE_2MB, PTE_P | PTE_W | PTE_G | PTE_NX);
	if (ret)
		goto fail;

	/* step 3: precision map phdr, heap, stack, vdso, and vvar sections */
	ret = procmap_iterate(&entry_procmap_cb, (unsigned long)layout);
	if (ret)
		goto fail;

	if(!linux_has_vvar) {
		ret = entry_setup_oldstyle_vvar();
		if (ret)
			goto fail;
	}

	/* step 4: map the system call handler page */
	ret = entry_setup_syscall();
	if (ret)
		goto fail;

	return 0;

fail:
	vm_destroy_pt(kern_pgtbl);
	return ret;
}

/**
 * entry_init - initialization for entry
 */
int entry_init(void)
{
	int ret;
	struct dune_layout layout;

	dune_fd = open("/dev/dune", O_RDWR);
	if (dune_fd < 0) {
		log_err("entry: failed to open dune device\n");
		return -EIO;
	}

	entry_init_idt();

	ret = entry_init_layout(&layout);
	if (ret) {
		log_err("entry: unable to get dune memory layout\n");
		return ret;
	}

	ret = entry_init_pgtbl(&layout);
	if (ret) {
		log_err("entry: failed to create kernel page table\n");
		return ret;
	}

	return 0;
}

static __thread uint64_t gdt[GDT_ENTRIES] __aligned(CACHE_LINE_SIZE);
static __thread struct tssd tss __aligned(CACHE_LINE_SIZE);
static __thread struct entry_percpu cpu_entry;

/* FIXME: protect the stacks with guard pages */
static int entry_setup_stacks(struct tssd *tss)
{
	int i;
	struct page *safe_stack_pg, *intr_stack_pg;
	char *safe_stack, *intr_stack;

	safe_stack_pg = page_alloc(PGSIZE_4KB);
	if (!safe_stack_pg)
		return -ENOMEM;

	safe_stack = page_to_addr(safe_stack_pg);
	safe_stack += PGSIZE_4KB;
	tss->iomb = offsetof(struct tssd, iopb);

	for (i = 0; i < 8; i++)
		tss->ist[i] = (uintptr_t) safe_stack;

	intr_stack_pg = page_alloc(PGSIZE_4KB);
	if (!intr_stack_pg) {
		page_put_addr(safe_stack_pg);
		return -ENOMEM;
	}

	intr_stack = page_to_addr(intr_stack_pg);
	intr_stack += PGSIZE_4KB;
	tss->rsp[0] = (uintptr_t)intr_stack;
	kern_sp = (uintptr_t)intr_stack;

	return 0;
}

static int entry_start_dune(void)
{
	struct dune_config conf;
	int ret;

	conf.rip = (uintptr_t)&__dune_ret;
	conf.rsp = 0;
	conf.cr3 = (uintptr_t)kern_pgtbl;

	ret = __dune_enter(dune_fd, &conf);
	if (ret) {
		log_err("entry: failed to enter dune mode\n");
		return ret;
	}

	return 0;
}

static int entry_boot_cpu(struct entry_percpu *ent,
			  uintptr_t gdt_addr, uintptr_t idt_addr)
{
	struct tptr _idtr, _gdtr;

	_gdtr.base  = gdt_addr;
	_gdtr.limit = sizeof(gdt_template) - 1;

        _idtr.base = idt_addr;
        _idtr.limit = sizeof(idt_template) - 1;

        asm volatile(
                /* STEP 1: load the new GDT */
                "lgdt %0\n"

                /* STEP 2: initialize data segements */
                "mov $" __str(GD_KD) ", %%ax\n"
                "mov %%ax, %%ds\n"
                "mov %%ax, %%es\n"
                "mov %%ax, %%ss\n"

                /* STEP 3: long jump into the new code segment */
                "mov $" __str(GD_KT) ", %%rax\n"
                "pushq %%rax\n"
                "pushq $1f\n"
                "lretq\n"
                "1: nop\n"

                /* STEP 4: load the task register (for safe stack switching) */
                "mov $" __str(GD_TSS) ", %%ax\n"
                "ltr %%ax\n"

                /* STEP 5: load the new IDT */
                "lidt %1\n"

                : : "m" (_gdtr), "m" (_idtr) : "rax");

        /* STEP 6: FS and GS require special initialization on 64-bit */
        setfsbase(ent->kfs_base);
        setgsbase((uintptr_t)ent);
	setgskernbase((uintptr_t)ent);
	irq_enable();

        return 0;
}

extern int arch_prctl(int code, unsigned long *addr);

/*
 * entry_init_one - per-cpu initialization for entry
 */
int entry_init_one(void)
{
	int ret;
	int numa_node = thread_numa_node;
	struct entry_percpu *ent = &cpu_entry;
	unsigned long fs_base;

	/* step 1: set up the TSS */
	ret = entry_setup_stacks(&tss);
	if (ret)
		return ret;

	/* step 2: set up the GDT */
        memcpy(gdt, gdt_template, sizeof(gdt_template));
	gdt[GD_TSS >> 3] = (SEG_TSSA | SEG_P | SEG_A |
				    SEG_BASELO(&tss) |
				    SEG_LIM(sizeof(struct tssd) - 1));
	gdt[GD_TSS2 >> 3] = SEG_BASEHI(&tss);

	/* step 3: set up the IDT */
	spin_lock(&entry_lock);
	if (!idt_node[numa_node]) {
		struct page *pg = page_alloc_on_node(PGSIZE_4KB, numa_node);
		if (!pg) {
			spin_unlock(&entry_lock);
			return -ENOMEM;
		}

		BUILD_ASSERT(sizeof(idt_template) <= PGSIZE_4KB);
		idt_node[numa_node] = page_to_addr(pg);
		memcpy(idt_node[numa_node], idt_template, sizeof(idt_template));
	}
	spin_unlock(&entry_lock);

	/* step 4: setup the entry per-cpu structure */
	if (arch_prctl(ARCH_GET_FS, &fs_base) == -1) {
		log_err("entry: failed to get current FS.base\n");
		return -EIO;
	}

	ent->kfs_base = fs_base;
	ent->ugs_base = 0;

	/* step 5: enter dune mode */
	ret = entry_start_dune();
	if (ret)
		return ret;

	/* step 6: set up architectural state */
	ret = entry_boot_cpu(ent, (uintptr_t)gdt,
			     (uintptr_t)idt_node[numa_node]);
	if (ret)
		return ret;

	return 0;
}
