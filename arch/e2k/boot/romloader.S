//
// rom_loader.S, written by <karbo@lab.sun.mcst.ru>
// secondary kernel startup module
//



#ifdef	_E2K_SIMULATION_MODE_
#include <asm/simul.h>
#endif	/* _E2K_SIMULATION_MODE_ */
#include <asm/head.h>
#include <asm/cpu_regs.h>
#ifdef	CONFIG_E2K_LEGACY_SIC
#include <asm/hb_regs.h>
#endif	/* CONFIG_E2K_LEGACY_SIC */
#ifdef	CONFIG_SMP
#include <asm/apicdef.h>
#include <asm/mas.h>
#endif	/* CONFIG_SMP */

#define	MMU_TRAP_CELLAR_MAX_SIZE	64	/* double-words */

#define RW		0x1800000000000000
#define R		0x0800000000000000
#define RW_NONP		0x1800000000000000

#define RBS		0x10 			/* 10 quadwords	*/

#define	NMIE_PSR	0x20		/* enable nm-interrupts */

.section "text"
.global loader

.global _data
.global __bios_size_ld
.global __bios_fsize_ld
.global __bios_entry_ld
.global __bios_start_data
.global __bios_size_data
.global __bios_size_data_plus_bss

// loader will call jump() to continue. See jumpstart.c
.global jump
.global free_memory_p

#ifdef	CONFIG_SMP
.global cpu_count
.global phys_cpu_count
.global all_apic_ids
#endif	/* CONFIG_SMP */

loader:
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

#ifdef	CONFIG_SMP

// read APIC_BSP register

	addd,1	APIC_BSP, APIC_DEFAULT_PHYS_BASE, %dr0	// APIC_BSP reg addr
	ldw,2	[%dr0] MAS_IOADDR, %r0		// read APIC_BSP
	disp	%ctpr1, cpu_is_BSP
	ands,0	%r0, APIC_BSP_IS_BSP, %r0	// is CPU BSP?
	cmpesb	%r0, 0, %pred0
	ct	%ctpr1 ? ~%pred0
	addd,0	0, [cpu_count], %dr1
#ifndef	CONFIG_E2K_SIC
waiting_for_cpu_count_0:
	ldw,0	[%dr1], %r0			// load cpu_count
	disp	%ctpr1, waiting_for_cpu_count_0
	cmpesb	%r0, 0, %pred0			// cpu_count == 0 ?
	ct	%ctpr1 ? ~%pred0		// go waiting_for_cpu_count_0

waiting_for_cpu_count_1:
	ldw,0	[%dr1], %r0			// load cpu_count
	disp	%ctpr1, waiting_for_cpu_count_1
	cmpesb	%r0, 0, %pred0			// cpu_count != 0 ?
	ct	%ctpr1 ? %pred0			// go waiting_for_cpu_count_1

waiting_for_lock:
	ldw,0	[%dr1] MAS_WAIT_LOCK, %r0
{
	adds,0	%r0, 1, %r0
	adds,1	%r0, 0, %r2
}
{
	stw,2	%r0, [%dr1] MAS_WAIT_UNLOCK
	ibranch	waiting_for_lock ? #MLOCK
}
	sxt,0	6, %r2, %dr2			// E3M AP CPU #
#endif	/* ! CONFIG_E2K_SIC */
	addd,1	0, (APIC_ID + APIC_DEFAULT_PHYS_BASE), %dr0 // APIC_ID reg addr
	ldw,2	[%dr0] MAS_IOADDR, %r0		// read APIC_ID
	shrs,0	%r0, APIC_ID_SHIFT, %r0
	ands,0	%r0, APIC_ID_BIT_MASK, %r0
#ifdef	CONFIG_E2K_SIC
	ldw,0	[%dr1], %r2			// load cpu_count
	adds,0	%r2, 1, %r2			// cpu_count ++
	stw,2	%r2, [%dr1]			// save cpu_count
	sxt,0	6, %r2, %dr2			// E3S AP CPU #
#endif	/* CONFIG_E2K_SIC */
	shld,0	%dr2, 2, %dr2
	stw,2	%r0, [%dr2 + all_apic_ids]

	addd,0	0, [phys_cpu_count], %dr1
waiting_for_cpus_startup:
	ldw,0	[%dr1], %r0			// load phys_cpu_count
	disp	%ctpr1, waiting_for_cpus_startup
	cmpesb	%r0, 0, %pred0			// phys_cpu_count != 0 ?
	ct	%ctpr1 ? %pred0			// go waiting_for_cpus_startup

// reset APIC_NM register

	addd,1	0, APIC_DEFAULT_PHYS_BASE, %dr0	// APIC_NM reg addr
	addd	%dr0, APIC_NM, %dr0		//
	ors	0, APIC_NM_BIT_MASK, %r1	// initial state of APIC_NM
	stw,2	%r1, [%dr0] MAS_IOADDR		// reset APIC_BSP
	addd,1	0, APIC_DEFAULT_PHYS_BASE, %dr0	// APIC_EOI reg addr
	addd	%dr0, APIC_EOI, %dr0		// end of interrupt
	ors	0, APIC_EOI_ACK, %r1
	stw,2	%r1, [%dr0] MAS_IOADDR

	rrs	%psr, %r1
	ors	%r1, NMIE_PSR, %r1
	rws	%r1, %psr
waiting_for_apic_startup:
	nop	4
	disp	%ctpr1, waiting_for_apic_startup
	ct	%ctpr1

cpu_is_BSP:

#endif	/* CONFIG_SMP */

// copy BIOS .data segment from ROM to RAM

#ifdef	CONFIG_E2K_LEGACY_SIC

#define PCI_DEVFN(slot, func)	((((slot) & 0x1f) << 3) | ((func) & 0x07))
#define CONFIG_CMD(bus, devfn, where)  	\
		((bus & 0xff) << 20) | ((devfn & 0xff) << 12) | (where & 0xfff)
#define	HB_REG_ADDR(reg_offset)						\
		CONFIG_CMD(HB_PCI_BUS_NUM,				\
				PCI_DEVFN(HB_PCI_SLOT, HB_PCI_FUNC),	\
				reg_offset)
#define	E1CP_BIOS_DATA_RAM_SIZE	0x1000000	/* 16M */

// Set low memory size to enable copiing data segment to RAM

	addd	0, E1CP_PCICFG_AREA_PHYS_BASE, %dr4
	addd	0, E1CP_BIOS_DATA_RAM_SIZE, %dr0
	stw	%dr0, [%dr4 + HB_REG_ADDR(HB_PCI_TOM)] MAS_IOADDR
#endif	/* CONFIG_E2K_SIC */

        disp %ctpr1,looper

        addd 0, EOS_RAM_BASE, %r4


        addd 0, [__bios_start_data], %r6	// BIOS RW data segment address 
						// in ROM
        addd 0, [__bios_size_data], %r8		// BIOS RW data segment size

	subd %r8, 16, %r8			// size-=16 due to ROM copying 
						// cycle organization

	addd 0, [__bios_size_data_plus_bss], %r0 // BIOS RW data+BSS size
	subd %r0, 32, %r0			// size-=32 due to BSS clearing 
						// cycle organization (ct after
						// move completed - 16,
						// ct evaluates %pred on next 
						// iteration only - 16
	addd %r6, %r8, %r2			// EOS ending point in ROM
	addd %r4, %r0, %r8			// EOS+BSS ending point in RAM

looper:
        cmpbesb %r2,%r6, %pred0
	ldd [%r6], %r0
	ldd [%r6+8], %r12
	addd %r6, 16, %r6
	std %r0, [%r4]
	std %r12, [%r4+8]
	addd %r4, 16, %r4
        ct %ctpr1 ? ~%pred0


// clear BSS

	disp %ctpr1, looper_bss
	addd 0, 0, %r0

looper_bss:
	cmpbesb %r8, %r4, %pred0
	std %r0, [%r4]
	std %r0, [%r4+8]
	addd %r4, 16, %r4
	ct %ctpr1 ? ~%pred0

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
	addd 0,	[jump], %r2
	movtd	%r2, %ctpr1


	setwd	wsz=RBS+4

// Call jump() and fly away
	call	%ctpr1, wbs=RBS
	.size loader, . - loader
	
