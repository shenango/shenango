/*
 * trapasm.S - assembly helper routines (e.g. system calls, interrupts, traps)
 */

/*
 * Enabling USE_RDRWGSFS can reduce system call overhead but this feature
 * is only available on Ivy Bridge and later Intel CPUs.
 *
 * FIXME: detect this automatically
 */

#define MSR_FS_BASE	0xc0000100
#define MSR_GS_BASE	0xc0000101
#define GD_KT		0x10
#define GD_KD		0x18
#define GD_UD		0x28 | 0x03
#define GD_UT		0x30 | 0x03

/*
 * Trap Frame Format
 * NOTE: this reflects the layout of struct dune_tf
 */

/* arguments */
#define RDI	(0)
#define RSI	(8)
#define RDX	(16)
#define RCX	(24)
#define R8	(32)
#define R9	(40)

/* other registers */
#define R10	(48)
#define R11	(56)
#define RBX	(64)
#define RBP	(72)
#define R12	(80)
#define R13	(88)
#define R14	(96)
#define R15	(104)

#define REG_END	(112)

/* syscall num / return code */
#define RAX	(112)

/* exception frame */
#define ERR	(120)
#define RIP	(128)
#define CS	(136)
#define RFLAGS	(144)
#define RSP	(152)
#define SS	(160)

#define EF_START (128)
#define TF_END	(168)
#define TF_ALIGN (176)

/*
 * Dune Config Format
 * NOTE: this reflects the layout of struct dune_config
 */
#define DUNE_CFG_RIP	(0)
#define DUNE_CFG_RSP	(8)
#define DUNE_CFG_CR3	(16)
#define DUNE_CFG_RET	(24)

/*
 * Supervisor Private Area Format
 */
#define TMP		(8)
#define KFS_BASE	(16)
#define UFS_BASE	(24)
#define UGS_BASE	(32)
#define FLAGS		(40)
#define THREAD_STACK	(48)

#define FLAG_IN_USER	0x1
#define FLAG_LOAD_USER	0x2


.text

/*
 * macro to save destructable register state
 */
	.macro SAVE_REGS save_full=1, include_rax=1
	movq	%rdi, RDI(%rsp)
	movq	%rsi, RSI(%rsp)
	movq	%rdx, RDX(%rsp)
	movq	%r8, R8(%rsp)
	movq	%r9, R9(%rsp)

	.if \save_full
	movq	%r10, R10(%rsp)
	movq	%r11, R11(%rsp)
	movq	%rcx, RCX(%rsp)
	.endif

	.if \include_rax
	movq	%rax, RAX(%rsp)
	.endif
	.endm

/*
 * macro to save the rest of register state
 *
 * useful for operations that violate AMD64 calling conventions
 * by destroying callee restored state
 */
	.macro SAVE_REST
	movq	%rbx, RBX(%rsp)
	movq	%rbp, RBP(%rsp)
	movq	%r12, R12(%rsp)
	movq	%r13, R13(%rsp)
	movq	%r14, R14(%rsp)
	movq	%r15, R15(%rsp)
	.endm

/*
 * macro to restore destructable register state
 */
	.macro RESTORE_REGS rstor_full=1, include_rax=1
	.if \include_rax
	movq	RAX(%rsp), %rax
	.endif

	.if \rstor_full
	movq	RCX(%rsp), %rcx
	movq	R11(%rsp), %r11
	movq	R10(%rsp), %r10
	.endif

	movq	R9(%rsp), %r9
	movq	R8(%rsp), %r8
	movq	RDX(%rsp), %rdx
	movq	RSI(%rsp), %rsi
	movq	RDI(%rsp), %rdi
	.endm

/*
 * macro to restore the rest of register state
 *
 * useful for operations that violate AMD64 calling conventions
 * by destroying callee restored state
 */
	.macro RESTORE_REST
	movq	R15(%rsp), %r15
	movq	R14(%rsp), %r14
	movq	R13(%rsp), %r13
	movq	R12(%rsp), %r12
	movq	RBP(%rsp), %rbp
	movq	RBX(%rsp), %rbx
	.endm

/*
 * macro to setup FS and GS segments for kernel mode
 */
	.macro SETUP_KERNEL_SEGS
	movq	$0, %gs:FLAGS
	.endm

/*
 * macro to setup FS and GS segments for user mode
 *
 * NOTE: clobbers %rax, %rdx, and %rcx
 * WARNING: unsafe if interrupts are not disabled
 */
	.macro SETUP_USER_SEGS check=1
	orq	$FLAG_IN_USER, %gs:FLAGS

	.if \check
	testq	$FLAG_LOAD_USER, %gs:FLAGS
	jz 1f
	.endif

	movq	%gs:UFS_BASE, %rax
#ifdef USE_RDWRGSFS
	wrfsbase %rax
#else
	movq	%rax, %rdx
	shrq	$32, %rdx
	movl	$MSR_FS_BASE, %ecx
	wrmsr
#endif /* USE_RDWRGSFS */

	movq	%gs:UGS_BASE, %rax
	swapgs
#ifdef USE_RDWRGSFS
	wrgsbase %rax
#else
	movq	%rax, %rdx
	shrq	$32, %rdx
	movl	$MSR_GS_BASE, %ecx
	wrmsr
#endif /* USE_RDWRGSFS */

	.if \check
	jmp 2f
1:	swapgs
2:
	.endif
	.endm


.globl __dune_enter
__dune_enter:
	subq	$REG_END, %rsp
	SAVE_REGS 1, 0
	SAVE_REST
	movq	%rsp, DUNE_CFG_RSP(%rsi)
	movq	%rsi, %rdx
	movq	$0x8020e901, %rsi /* XXX DUNE_ENTER */
	movq	$16, %rax /* __NR_ioctl */
	syscall

	cmpq	$0, %rax
	jnz	__dune_ret
	mov	%rdx, %rbx
	call	init_shutdown_late
	movq	DUNE_CFG_RET(%rbx), %rdi
	movq	$231, %rax /* __NR_exit_group */
	syscall

.globl	__dune_ret
__dune_ret:
	RESTORE_REST
	RESTORE_REGS 1, 0
	addq	$REG_END, %rsp
	retq

/*
 * System Call ABI
 * ---------------
 *
 * User Parameters:
 * %rsp - stack pointer
 * %rcx - instruction pointer
 * %r11 - eflags
 * %rax - system call number
 *
 * Arguments:
 * %rdi - arg0, %rsi - arg1, %rdx - arg2
 * %r10 - arg3, %r8 - arg4, %r9 - arg5
 *
 * Return code goes in %rax
 *
 * XXX: don't do relative jumps - watch out code is memcpy
 * XXX: Invoked with interrupts disabled...
 */
.globl syscall_enter
syscall_enter:
	/*
	 * Hack to redirect any syscall instructions executed
	 * in kernel mode to the hypervisor through vmcall.
	 */
	swapgs
	testq $FLAG_IN_USER, %gs:FLAGS
	jnz 1f
	pushq	%r11
	popfq
	vmcall
	jmp	*%rcx

1:
	/* first switch to the kernel stack */
	movq	%rsp, %gs:TMP
	movq	%gs:THREAD_STACK, %rsp

	/* now push the trap frame onto the stack */
	subq	$TF_END, %rsp
	movq	%rcx, RIP(%rsp)
	movq	%r11, RFLAGS(%rsp)
	movq	%r10, RCX(%rsp) /* fixup to standard 64-bit calling ABI */
	SAVE_REGS 0, 1
	SAVE_REST
	movq	%gs:TMP, %rax
	movq	%rax, RSP(%rsp)

	/* configure the segment bases */
	SETUP_KERNEL_SEGS

	/* then finally re-enable interrupts and jump to the handler */
	sti
	movq	%rsp, %rdi /* argument 0 */
	lea	syscall_handler, %rax
	call	*%rax
	cli

	/* restore the segment bases */
	SETUP_USER_SEGS

	/* then pop the trap frame off the stack */
	RESTORE_REGS 0, 1
	RESTORE_REST
	movq	RCX(%rsp), %r10
	movq	RFLAGS(%rsp), %r11
	movq	RIP(%rsp), %rcx

	/* switch to the user stack and return to ring 3 */
	movq	RSP(%rsp), %rsp
	sysretq

.globl syscall_enter_end
syscall_enter_end:
	nop

.globl pop_tf
pop_tf:
	/* restore callee regs */
	movq    RBX(%rdi), %rbx
	movq    RBP(%rdi), %rbp
	movq    R12(%rdi), %r12
	movq    R13(%rdi), %r13
	movq    R14(%rdi), %r14
	movq    R15(%rdi), %r15

	/* restore ip and stack */
	movq    RSP(%rdi), %rsp
	movq    RIP(%rdi), %rcx

	jmpq    *%rcx

.globl pop_tf_user
pop_tf_user:
	movq	%rdi, %rsp /* might not be a stack! */
	SETUP_USER_SEGS 0
	RESTORE_REGS
	RESTORE_REST
	addq	$EF_START, %rsp
	iretq

.globl pop_tf_user_fast
pop_tf_user_fast:
	movq	%rdi, %rsp /* might not be a stack! */
	SETUP_USER_SEGS 0
	RESTORE_REGS 0, 1
	RESTORE_REST
	movq	R10(%rsp), %r10
	movq	RIP(%rsp), %rcx
	movq	RFLAGS(%rsp), %r11
	movq	RSP(%rsp), %rsp
	sysretq

/**
 * switch_tf - saves the current kernel frame and pops
 *             the next kernel frame
 * @cur: the current trap frame
 * @next: the next trap frame
 */
.globl switch_tf
switch_tf:
	/* save callee regs */
	movq    %rbx, RBX(%rdi)
	movq    %rbp, RBP(%rdi)
	movq    %r12, R12(%rdi)
	movq    %r13, R13(%rdi)
	movq    %r14, R14(%rdi)
	movq    %r15, R15(%rdi)

	/* save ip and stack */
	movq    (%rsp), %rcx
	movq    %rcx, RIP(%rdi)
	leaq    8(%rsp), %rcx
	movq    %rcx, RSP(%rdi)

	/* restore callee regs */
	movq    RBX(%rsi), %rbx
	movq    RBP(%rsi), %rbp
	movq    R12(%rsi), %r12
	movq    R13(%rsi), %r13
	movq    R14(%rsi), %r14
	movq    R15(%rsi), %r15

	/* restore ip and stack */
	movq    RSP(%rsi), %rsp
	movq    RIP(%rsi), %rcx

	/* restore arguments (in case new thread) */
	movq    RDI(%rsi), %rdi # ARG0
	movq	RSI(%rsi), %rsi # ARG1

	jmpq    *%rcx

/*
 * NOTE: interrupts start out disabled.
 * The macro generates a fixed-sized array of handlers, one for each vector.
 */
.globl trap_entry_tbl
.align 16
trap_entry_tbl:
	i = 0
	.rept 256
	.align 16
	.if i <> 8 && (i <= 9 || i >= 15) && i <> 17
		pushq	%rax /* placeholder for no error code */
	.endif
	pushq	%rax /* save %rax */
	mov $i, %rax
	jmp 1f
	i = i + 1
	.endr

1:
	/* save the remaining destructable registers */
	subq	$REG_END, %rsp
	SAVE_REGS 1, 0 /* %rax already is pushed */
	SAVE_REST
	movq	%rax, %rdi

	/* determine if we were in user mode before the trap */
	testq	$3, CS(%rsp)
	jz	2f
	swapgs
	SETUP_KERNEL_SEGS

2:
	sti
	/* setup arguments and call the handler */
	movq	%rsp, %rsi
	call	trap_handler

	/* determine if we're returning to user mode */
	testq	$3, CS(%rsp)
	jz	3f

	/* return to user mode */
	cli
	SETUP_USER_SEGS
	RESTORE_REGS
	addq	$EF_START, %rsp
	iretq

	/*
	 * This is the exception return fast path. It is only
	 * available when returning to the kernel instead of user
	 * space. The reason it is faster is that iretq has a
	 * fair amount of overhead and we can avoid that by using
	 * a regular retq instead.
	 */
3:
	movq    RIP(%rsp), %rax
	movq    RSP(%rsp), %rcx
	subq    $8, %rcx
	movq    %rax, (%rcx) /* XXX: this overwrites SS in the trap frame */
	movq    %rcx, RSP(%rsp)
	movq    RFLAGS(%rsp), %rcx
	pushq   %rcx
	popfq
	RESTORE_REGS

	/* jump to the frame */
movq    RSP(%rsp), %rsp
	retq
