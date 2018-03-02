/*
 * tf.S - assembly routines for switching trap frames
 */

/*
 * Trap Frame Format
 * WARNING: These values reflect the layout of struct thread_tf. Don't change
 * these values without also updating defs.h.
 */

/* arguments registers (can be clobbered) */
#define RDI	(0)
#define RSI	(8)
#define RDX	(16)
#define RCX	(24)
#define R8	(32)
#define R9	(40)

/* temporary registers (can be clobbered) */
#define R10	(48)
#define R11	(56)

/* callee-saved registers (can not be clobbered) */
#define RBX	(64)
#define RBP	(72)
#define R12	(80)
#define R13	(88)
#define R14	(96)
#define R15	(104)

/* special-purpose registers */
#define RAX	(112)	/* return code */
#define RIP	(120)	/* instruction pointer */
#define RSP	(128)	/* stack pointer */

/**
 * __jmp_thread - executes a thread from the runtime
 * @tf: the trap frame to pop (%rdi)
 *
 * This low-level variant isn't intended to be called directly.
 * Re-enables preemption, parking the kthread if necessary.
 * Does not return.
 */
.globl __jmp_thread
__jmp_thread:
	/* restore callee regs */
	movq    RBX(%rdi), %rbx
	movq    RBP(%rdi), %rbp
	movq    R12(%rdi), %r12
	movq    R13(%rdi), %r13
	movq    R14(%rdi), %r14
	movq    R15(%rdi), %r15

	/* restore ip and stack */
	movq    RSP(%rdi), %rsp
	movq    RIP(%rdi), %rsi

	/* set first argument (in case new thread) */
	movq    RDI(%rdi), %rdi /* ARG0 */

	/* re-enable preemption */
	decl	%fs:preempt_cnt@tpoff
	jz	1f

	/* jump into trap frame */
	jmpq    *%rsi
	nop

1:	/* cold-path, save RIP and park the kthread */
	pushq	%rsi
	pushq	%rdi
	call	preempt
	popq	%rdi
	popq	%rsi
	jmpq	*%rsi

/**
 * __jmp_runtime - saves the current trap frame and jumps to a function in the
 *                 runtime
 * @tf: the struct thread_tf to save state (%rdi)
 * @fn: the function pointer to call (%rsi)
 * @stack: the start of the runtime stack (%rdx)
 * @arg: an argument to @fn (%rcx)
 *
 * This low-level variant isn't intended to be called directly.
 * Must be called with preemption disabled.
 * No return value.
 */
.globl __jmp_runtime
__jmp_runtime:
	/* save callee regs */
	movq    %rbx, RBX(%rdi)
	movq    %rbp, RBP(%rdi)
	movq    %r12, R12(%rdi)
	movq    %r13, R13(%rdi)
	movq    %r14, R14(%rdi)
	movq    %r15, R15(%rdi)

	/* save ip and stack */
	movq    (%rsp), %r8
	movq    %r8, RIP(%rdi)
	leaq    8(%rsp), %r8
	movq    %r8, RSP(%rdi)

	/* jump into runtime function */
	movq    %rdx, %rsp
	movq	%rcx, %rdi

	/* jump into runtime code */
	jmpq    *%rsi

/**
 * __jmp_runtime_nosave - jumps to a function in the runtime without saving the
 *			  current stack frame
 * @fn: the function pointer to call (%rdi)
 * @stack: the start of the runtime stack (%rsi)
 * @arg: an argument to @fn (%rdx)
 *
 * This low-level variant isn't intended to be called directly.
 * Must be called with preemption disabled.
 * No return value.
 */
.globl __jmp_runtime_nosave
__jmp_runtime_nosave:

	/* jump into runtime function */
	movq    %rsi, %rsp
	movq	%rdi, %rsi
	movq	%rdx, %rdi

	/* jump into runtime code */
	jmpq    *%rsi

/**
 * __jmp_restore_sigctx - restores a ucontext frame recovered in a signal handler
 * @c: a pointer to the ucontext_t (%rdi)
 * @fpstate_offset: the observed offset for the pointer to the fpstate (%rsi)
 *
 * No return value.
 */
.globl __jmp_restore_sigctx
__jmp_restore_sigctx:
	/* Allocate stack space so fpstate ptr is 64 byte aligned */
	subq $0x2c8, %rsp               # allocate last 712 bytes of ucontext_t
	andq $0xffffffffffffff40,  %rsp # round down to multiple of 64
	subq $0xe0, %rsp                # allocate first 224 bytes of ucontext_t

	/* Calculate address of actual fpstate buffer inside copied ucontext_t */
	movq    %rsp, %rax
	addq    %rsi, %rax   # %rax := pointer + offset_to_fpstate

	/* Copy full ucontext_t to stack */
	movq    %rdi,  %rsi
	movq    %rsp,  %rdi
	movq    $0x75, %rcx
	rep movsq %ds:(%rsi),%es:(%rdi)

	/* Set 64-byte aligned pointer to point to fpstate buf */
	movq    %rax,0xe0(%rsp)

	/* syscall(SYS_rt_sigreturn) */
	movq    $0xf,%rax
	syscall
