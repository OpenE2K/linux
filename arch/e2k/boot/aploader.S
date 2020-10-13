//
// aploader.s, written by <atic@mcst.ru>
// secondary linux kernel loader module on application processor
//

#ifdef	_E2K_SIMULATION_MODE_
#include <asm/simul.h>
#endif	/* _E2K_SIMULATION_MODE_ */
#include <asm/head.h>
#include <asm/cpu_regs.h>

#define	MMU_TRAP_CELLAR_MAX_SIZE	64	/* double-words */

#define RW		0x1800000000000000
#define R		0x0800000000000000
#define RW_NONP		0x1800000000000000

#define RBS		0x10 			/* 10 quadwords	*/

.section "text"
.global aploader

.global _data
.global __bios_size_ld
.global __bios_fsize_ld
.global __bios_entry_ld
.global __bios_start_data
.global __bios_size_data
.global __bios_size_data_plus_bss

// loader will call start_secondary() to continue. See smp.c
.global start_secondary
.global free_memory_p

aploader:
// [OS]{CUD|GD} setup
	addd 0, [__bios_size_ld], %r8		// EOS size
	addd 0, EOS_RAM_BASE+R, %r2
	addd %r2,1<<58 , %r2			// set CUD.c flag
	rwd %r2, %oscud.lo
	addd 0, EOS_RAM_BASE+RW, %r6
//	shld %r8, 32, %r10
	addd 0, 0x01f0000000000000, %r10	// *D size (all space 1M upward)

	rwd %r2, %cud.lo
	rwd %r6, %osgd.lo
	rwd %r6, %gd.lo

        rwd %r10, %oscud.hi
        rwd %r10, %osgd.hi
        rwd %r10, %cud.hi
        rwd %r10, %gd.hi

	ldd	[free_memory_p] , %dr4
// PSP - procedure stack pointer

// 'E2K_ALIGN_PSTACK' kernel loader procedure stack align
	addd	%r4, E2K_ALIGN_PSTACK_MASK, %r4
	andd	%r4, (~(E2K_ALIGN_PSTACK_MASK)),%r4

// 'E2K_KERNEL_PS_PAGE_SIZE' kernel loader procedure stack align
	addd	%r4, (E2K_KERNEL_PS_PAGE_SIZE - 1), %r4
	andd	%r4, (~(E2K_KERNEL_PS_PAGE_SIZE - 1)),%r4

	rwd	E2K_BOOT_KERNEL_PS_SIZE << 32, %psp.hi
	addd	%r4, RW, %r6
	rwd	%r6, %psp.lo
	addd	%r4, (E2K_BOOT_KERNEL_PS_SIZE + E2K_KERNEL_PS_PAGE_SIZE), %r4

// 'E2K_KERNEL_PS_PAGE_SIZE' kernel loader procedure stack align
	addd	%r4, (E2K_KERNEL_PS_PAGE_SIZE - 1), %r4
	andd	%r4, (~(E2K_KERNEL_PS_PAGE_SIZE - 1)),%r4

// PCSP - procedure chain stack pointer

// 'E2K_ALIGN_PCSTACK' kernel loader procedure chain stack align
	addd	%r4, E2K_ALIGN_PCSTACK_MASK, %r4
	andd	%r4, (~(E2K_ALIGN_PCSTACK_MASK)),%r4

// 'E2K_KERNEL_PCS_PAGE_SIZE' kernel loader procedure chain stack align
	addd	%r4, (E2K_KERNEL_PCS_PAGE_SIZE - 1), %r4
	andd	%r4, (~(E2K_KERNEL_PCS_PAGE_SIZE - 1)),%r4
	rwd	E2K_BOOT_KERNEL_PCS_SIZE << 32, %pcsp.hi
	addd	%r4, RW, %r6

	rwd	%r6, %pcsp.lo
	addd	%r4, (E2K_BOOT_KERNEL_PCS_SIZE + E2K_KERNEL_PCS_PAGE_SIZE), %r4
// 'E2K_KERNEL_PCS_PAGE_SIZE' kernel loader procedure chain stack align
	addd	%r4, (E2K_KERNEL_PCS_PAGE_SIZE - 1), %r4
	andd	%r4, (~(E2K_KERNEL_PCS_PAGE_SIZE - 1)),%r4

// US - user (kernel loader) stack pointer

// 'E2K_ALIGN_USTACK' kernel loader stack align
	addd	%r4, E2K_ALIGN_USTACK_MASK, %r4
	andd	%r4, (~(E2K_ALIGN_USTACK_MASK)),%r4

// 'E2K_KERNEL_US_PAGE_SIZE' kernel loader stack align

// User Stack is supposed to grow from higher memory addresses to lower ones
// Switch to higher memory addresses of stack
	addd	%r4, E2K_BOOT_KERNEL_US_SIZE, %r4
	addd	%r4, (E2K_KERNEL_US_PAGE_SIZE - 1), %r4
	andd	%r4, (~(E2K_KERNEL_US_PAGE_SIZE - 1)),%r4
	rwd	E2K_BOOT_KERNEL_US_SIZE << 32, %usd.hi
	addd	%r4, E2K_ALIGN_STACKS_BASE_MASK, %r4
	andd	%r4, (~(E2K_ALIGN_STACKS_BASE_MASK)), %r4
	rwd	%r4, %sbr
	addd	%r4, RW_NONP, %r6
	rwd	%r6, %usd.lo

// Trap Cellar
	std	%r0, [0x0] 71
	std	%r4, [0x00000050] 71
	addd	%dr4, MMU_TRAP_CELLAR_MAX_SIZE * 8, %dr4
	std	%dr4, [free_memory_p]

// Jump to the rtc0 (preparation)
	addd 0,	[start_secondary], %r2
	movtd	%r2, %ctpr1

	setwd	wsz=RBS+4

// Call start_secondary() and fly away
	call	%ctpr1, wbs=RBS
