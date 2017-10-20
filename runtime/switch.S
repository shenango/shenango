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
 * __pop_tf - pops a stack frame
 * @tf: the trap frame to pop (%rdi)
 *
 * This low-level variant isn't intended to be called directly.
 *
 * Does not return.
 */
.globl __pop_tf
__pop_tf:
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

	/* jump into trap frame */
	jmpq    *%rsi

/**
 * __call_runtime - saves the current trap frame and calls a function in the
 *                  runtime
 * @tf: the struct thread_tf to save state (%rdi)
 * @fn: the function pointer to call (%rsi)
 * @stack: the start of the runtime stack (%rdx)
 * @arg: an argument to @fn (%rcx)
 *
 * This low-level variant isn't intended to be called directly.
 *
 * No return value.
 */
.globl __call_runtime
__call_runtime:
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
	jmpq    *%rsi
