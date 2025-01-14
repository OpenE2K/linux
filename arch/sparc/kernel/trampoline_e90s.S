#include <linux/init.h>
#include <linux/version.h>
#include <asm/thread_info.h>
#include <asm/ptrace.h>
#include <asm/asi.h>
#include <asm/e90s.h>


	.align		8
	.globl		sparc64_cpu_startup, sparc64_cpu_startup_end
sparc64_cpu_startup:

	set	cpu_new_thread, %g6
	ldx	[%g6], %g6

	wrpr	%g0, 0, %wstate

	call		setup_trap_table
	nop

	mov	1, %g1
	sllx	%g1, THREAD_SHIFT, %g1
	sub	%g1, (STACKFRAME_SZ + STACK_BIAS), %g1
	add	%g6, %g1, %sp
	mov	0, %fp

	ldx	[%g6 + TI_TASK], %g4

	call		smp_callin
	 nop
	call		cpu_panic
	 nop
1:	b,a,pt		%xcc, 1b


	.align		8
sparc64_cpu_startup_end:
