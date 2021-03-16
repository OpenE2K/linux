/* $Id: head.h,v 1.41 2009/10/27 10:14:51 atic Exp $ */
#ifndef _E2K_HEAD_H
#define	_E2K_HEAD_H

#include <asm/types.h>
#include <asm/p2v/boot_v2p.h>
#include <asm/page.h>
#include <asm/e2k_api.h>
#ifndef __ASSEMBLY__
#include <asm/sections.h>
#endif /* _ASSEMBLY__ */

#define	EOS_RAM_BASE_LABEL	_data
#define	KERNEL_START_LABEL	_start		/* start label of Linux Image */
#define	KERNEL_END_LABEL	_end		/* end label of Linux Image */

#define	TTABLE_START_LABEL	__ttable_start	/* start label of kernel */
						/* trap table */
#define	TTABLE_END_LABEL	__ttable_end	/* end label of kernel */
						/* trap table */

#ifdef __ASSEMBLY__

#define	KERNEL_BASE	[KERNEL_START_LABEL]	/* virtual address of Linux */
						/* Image begining */
#define	KERNEL_END	[KERNEL_END_LABEL]	/* virtual address of Linux */
						/* Image end */
#define	EOS_RAM_BASE	[EOS_RAM_BASE_LABEL]

#define	KERNEL_TTABLE_BASE	[TTABLE_START_LABEL]	/* kernel trap table */
							/* start address */
#define	KERNEL_TTABLE_END	[TTABLE_END_LABEL]	/* kernel trap table */
							/* end address */

#else /* !(__ASSEMBLY__) */

#define	EOS_RAM_BASE	((e2k_addr_t)&EOS_RAM_BASE_LABEL)

#define	KERNEL_BASE	((e2k_addr_t)&KERNEL_START_LABEL)
#define	KERNEL_END	((e2k_addr_t)&KERNEL_END_LABEL)

#define	KERNEL_TTABLE_BASE	((e2k_addr_t)&TTABLE_START_LABEL)
#define	KERNEL_TTABLE_END	((e2k_addr_t)&TTABLE_END_LABEL)

#endif /* !(__ASSEMBLY__) */


#define	E2K_EOS_RAM_PAGE_SIZE	E2K_SMALL_PAGE_SIZE	/* Loader warks into */
							/* the small pages */

/* Size of pages where the kernel is loaded */
#define	E2K_KERNEL_PAGE_SIZE		(cpu_has(CPU_HWBUG_LARGE_PAGES) ? \
				E2K_SMALL_PAGE_SIZE : E2K_LARGE_PAGE_SIZE)
#define	BOOT_E2K_KERNEL_PAGE_SIZE	(boot_cpu_has(CPU_HWBUG_LARGE_PAGES) ? \
				E2K_SMALL_PAGE_SIZE : BOOT_E2K_LARGE_PAGE_SIZE)

							/* Equal map of phys */
							/* to virt addresses */
							/* should be done */
							/* into pages of one */
							/* size */
#define BOOT_E2K_EQUAL_MAP_PAGE_SIZE	BOOT_E2K_KERNEL_PAGE_SIZE

#define	E2K_KERNEL_PS_PAGE_SIZE	E2K_SMALL_PAGE_SIZE	/* kernel procedure */
							/* stack loads into */
							/* the small pages */

							/* kernel procedure */
							/* stack size 8 * 4KB */
							/* at boot-time */
#define	E2K_BOOT_KERNEL_PS_SIZE		(16 * E2K_KERNEL_PS_PAGE_SIZE)

							/* kernel procedure */
							/* chain stack loads */
							/* into the small */
							/* pages */
#define	E2K_KERNEL_PCS_PAGE_SIZE	E2K_SMALL_PAGE_SIZE

							/* kernel procedure */
							/* chain stack size */
							/* at boot-time */
							/* 4 * 4KB */
#define	E2K_BOOT_KERNEL_PCS_SIZE	(4 * E2K_KERNEL_PCS_PAGE_SIZE)

							/* kernel stack loads */
							/* into the small */
							/* pages */
#define	E2K_KERNEL_US_PAGE_SIZE		E2K_SMALL_PAGE_SIZE

							/* kernel stack size */
							/* at boot-time */
							/* 8 * 4KB */
#define	E2K_BOOT_KERNEL_US_SIZE		(4 * E2K_KERNEL_US_PAGE_SIZE)

							/* map initrd using */
							/* 4K pages (4Mb in */
							/* the future) */
#define	E2K_INITRD_PAGE_SIZE		E2K_SMALL_PAGE_SIZE

							/* map bootinfo data */
							/* using 4K pages    */
#define	E2K_BOOTINFO_PAGE_SIZE		E2K_SMALL_PAGE_SIZE

							/* map MP tables */
							/* using 4K pages */
#define	E2K_MPT_PAGE_SIZE		E2K_SMALL_PAGE_SIZE

							/* map symbols & */
							/* strings tables */
							/* using 4K pages    */
#define	E2K_NAMETAB_PAGE_SIZE		E2K_SMALL_PAGE_SIZE

							/* map x86 HW area   */
							/* using 4K pages    */
#define	E2K_X86_HW_PAGE_SIZE		E2K_SMALL_PAGE_SIZE

/*
 * All or some parts of physical memory pages are mapped to virtual
 * space starting from 'PAGE_OFFSET'
 */
#define	E2K_MAPPED_PHYS_MEM_SIZE	(0 * (1024 * 1024))
							/* full physical */
							/* memory */

/* Size of pages to map physical memory */
#define	E2K_MAPPED_PHYS_MEM_PAGE_SIZE	\
		((cpu_has(CPU_HWBUG_LARGE_PAGES) || \
		  IS_ENABLED(CONFIG_DEBUG_PAGEALLOC)) ? \
				E2K_SMALL_PAGE_SIZE : E2K_LARGE_PAGE_SIZE)
#define	BOOT_E2K_MAPPED_PHYS_MEM_PAGE_SIZE \
		((boot_cpu_has(CPU_HWBUG_LARGE_PAGES) || \
		  IS_ENABLED(CONFIG_DEBUG_PAGEALLOC)) ? \
				E2K_SMALL_PAGE_SIZE : BOOT_E2K_LARGE_PAGE_SIZE)

/*
 * Size of the top of kernel stack to map to equal virtual addresses to ensure
 * switching from physical to virtual addressing
 */
#ifndef __ASSEMBLY__
#define	E2K_KERNEL_US_PAGE_SWITCHING_SIZE	(128 * sizeof(long))
#else
#define	E2K_KERNEL_US_PAGE_SWITCHING_SIZE	(128 * 8)
#endif /* !(__ASSEMBLY__) */

/*
 * Kernel virtual memory layout
 */

/*
 * The topmost virtual addresses are used to allocate Virtually Mapped 
 * Linear Page Tables (VM LPT).
 * All page tables is virtually mapped into the same virtual space as kernel
 * Definition of Virtually Mapped Linear Page Table base address.
 * Virtual page table lives at the end of virtual addresses space
 * 0x0000 ff80 0000 0000 - 0x0000 ffff ffff ffff all PTs virtual space:
 *
 * 0x0000 ff80 0000 0000 - 0x0000 ffff bfff ffff first-level PTs (PTEs)
 * 0x0000 ffff c000 0000 - 0x0000 ffff ffdf ffff second-level PTs (PMDs)
 * 0x0000 ffff ffe0 0000 - 0x0000 ffff ffff efff third-level PTs (PUDs)
 * 0x0000 ffff ffff f000 - 0x0000 ffff ffff fffe root-fourth-level PTs (PGD)
 * 0x0000 ffff ffff ffff - root-fourth-level itself PGD
 */

#define	KERNEL_VPTB_BASE_ADDR		0x0000ff8000000000UL
#ifndef __ASSEMBLY__
#define	KERNEL_PPTB_BASE_ADDR		((e2k_addr_t)boot_root_pt)
#else
#define	KERNEL_PPTB_BASE_ADDR		(boot_root_pt)
#endif /* !(__ASSEMBLY__) */

/*
 * Area dedicated for I/O ports and BIOS physical memory
 * 0x0000 00ff fe00 0000 - 0x0000 00ff ffff ffff all I/O physical memory
 * 0x0000 ff7b fc00 0000 - 0x0000 ff7b ffff ffff all I/O virtual memory
 */

#define	E2K_KERNEL_IO_BIOS_AREAS_BASE	0x0000ff7bfc000000UL
#define	E2K_KERNEL_IO_BIOS_AREAS_SIZE	0x0000000004000000UL

/*
 * See BUG in pcim configuration block in jump func
 * should be 0x00000000FEBFFFFFUL due to specification
 */
#define E2K_PCI_MEM_AREA_PHYS_END		0x00000000F7FFFFFFUL
#define E2K_SCRB_SIZE				0x0000000000001000UL

#define	E2K_FULL_SIC_IO_AREA_PHYS_BASE		0x0000000101000000UL
#define	E2K_FULL_SIC_IO_AREA_SIZE		0x0000000000010000UL /* 64K */

#define	E2K_LEGACY_SIC_IO_AREA_PHYS_BASE	0x000000ff20000000UL
#define	E2K_LEGACY_SIC_IO_AREA_SIZE		0x0000000010000000UL /* 256M */

#define	E2K_VIRT_CPU_X86_IO_AREA_PHYS_BASE	0x000000fff0000000UL

/*
 * Area dedicated for I/O ports and BIOS physical memory
 * Area size should be max of
 *	E2K_FULL_SIC_IO_AREA_SIZE	0x0000000001000000UL
 *	E2K_LEGACY_SIC_BIOS_AREA_SIZE	0x0000000010000000UL	256 Mb IGNORE
 *
 * 0x0000 00ff f000 0000 - 0x0000 00ff ffff ffff all I/O physical memory
 * 0x0000 ff7b fc00 0000 - 0x0000 ff7b ffff ffff all I/O virtual memory
 *
 * see area dedication above :
 *
 * #define	E2K_KERNEL_IO_BIOS_AREAS_BASE	0x0000ff7bfc000000UL
 * #define	E2K_KERNEL_IO_BIOS_AREAS_SIZE	0x0000000004000000UL
 */

/*
 * Area dedicated for kernel resident image virtual space and virtual space
 * to allocate and load kernel modules.
 * Both this areas should be within 2 ** 30 bits of virtual adresses to provide
 * call of extern functions based on literal displacement DISP
 * 0x0000 e200 0000 0000 - 0x0000 e200 3fff ffff kernel image area with modules
 * 0x0000 e200 0000 0000 - 0x0000 e200 0xxx x000 kernel image area
 *					xxx x	 defined by kernel_image_size
 * 0x0000 e200 0xxx x000 - 0x0000 e200 3fff ffff area to load modules
 */
#define	NATIVE_KERNEL_IMAGE_AREA_BASE	0x0000e20000000000

#define	KERNEL_IMAGE_PGD_INDEX		pgd_index(E2K_KERNEL_IMAGE_AREA_BASE)

#define	E2K_KERNEL_IMAGE_AREA_SIZE	kernel_image_size
#define	E2K_MODULES_START		_PAGE_ALIGN_DOWN( \
						(E2K_KERNEL_IMAGE_AREA_BASE + \
						E2K_KERNEL_IMAGE_AREA_SIZE), \
						E2K_KERNEL_PAGE_SIZE)
#define	E2K_MODULES_END			(E2K_KERNEL_IMAGE_AREA_BASE + (1 << 30))
#define	E2K_KERNEL_AREAS_SIZE		0x0000000040000000UL	/* 2 ** 30 */

#define	KERNEL_CODES_INDEX		0UL	/* kernel CUI */
/* bug 114501: use 0 index for all unprotected executables */
#define	USER_CODES_UNPROT_INDEX(p) \
	((machine.native_iset_ver >= E2K_ISET_V6 || \
	  !(current->thread.flags & E2K_FLAG_32BIT)) ? 0UL : 1UL) /* user CUI */
#define	USER_CODES_PROT_INDEX		1UL	/* user protected codes */
						/* index */
#define	MAX_KERNEL_CODES_UNITS		(KERNEL_CODES_INDEX + 1)

#define	GUEST_CODES_INDEX		0UL
#define	HOST_CODES_INDEX		(KERNEL_CODES_INDEX)
#define	MAX_GUEST_CODES_UNITS		(GUEST_CODES_INDEX + 1)
#define	MAX_HOST_CODES_UNITS		(MAX_KERNEL_CODES_UNITS)

/*
 * Area dedicated for kernel symbols & strings tables
 * 0x0000 e200 4000 0000 - 0x0000 e200 ffff ffff kernel symbols & strings tables
 */
#define	E2K_KERNEL_NAMETAB_AREA_BASE	(E2K_KERNEL_IMAGE_AREA_BASE + \
						E2K_KERNEL_AREAS_SIZE)

/*
 * Area dedicated for physical memory mapping to virtual space
 * 0x0000 0000 0000 0000 - 0x0000 00ff ffff ffff all physical memory
 * 0x0000 d000 0000 0000 - 0x0000 d0ff ffff ffff all virtual memory to map
 *						 all physical memory
 */
#define	E2K_KERNEL_PHYS_MEM_VIRT_BASE	PAGE_OFFSET /* 0x0000d00000000000 */
#define	E2K_KERNEL_PHYS_MEM_SIZE	MAX_PM_SIZE /* == 2**40 - 2**48 */

/* virtualization support */
#include <asm/kvm/head.h>

/*
 * Kernel virtual memory context
 */
#define	E2K_KERNEL_CONTEXT		0x000

/*
 * CPU 'WAIT' operation fields structure
 */
#define	E2K_WAIT_OP_MA_C_MASK	0x20	/* wait for all previous memory */
					/* access operatons complete */
#define	E2K_WAIT_OP_FL_C_MASK	0x10	/* wait for all previous flush */
					/* cache operatons complete */
#define	E2K_WAIT_OP_LD_C_MASK	0x08	/* wait for all previous load */
					/* operatons complete */
#define	E2K_WAIT_OP_ST_C_MASK	0x04	/* wait for all previous store */
					/* operatons complete */
#define	E2K_WAIT_OP_ALL_E_MASK	0x02	/* wait for all previous operatons */
					/* issue all possible exceptions */
#define	E2K_WAIT_OP_ALL_C_MASK	0x01	/* wait for all previous operatons */
					/* complete */

/*
 * IMPORTANT NOTE!!!
 * Do not add 'sas' and 'sal' here, as they are modifiers
 * for st_c/ld_c which make them _less_ restrictive.
 */
#define	E2K_WAIT_OP_ALL_MASK	(E2K_WAIT_OP_MA_C_MASK |	\
				E2K_WAIT_OP_FL_C_MASK |		\
				E2K_WAIT_OP_LD_C_MASK |		\
				E2K_WAIT_OP_ST_C_MASK |		\
				E2K_WAIT_OP_ALL_C_MASK |	\
				E2K_WAIT_OP_ALL_E_MASK)

#define	E2K_WAIT_MA		E2K_WAIT(E2K_WAIT_OP_MA_C_MASK)
#define	E2K_WAIT_FLUSH		E2K_WAIT(E2K_WAIT_OP_FL_C_MASK)
#define	E2K_WAIT_LD		E2K_WAIT(E2K_WAIT_OP_LD_C_MASK)
#define	E2K_WAIT_ST		E2K_WAIT(E2K_WAIT_OP_ST_C_MASK)
#define	E2K_WAIT_ALL_OP		E2K_WAIT(E2K_WAIT_OP_ALL_C_MASK)
#define	E2K_WAIT_ALL_EX		E2K_WAIT(E2K_WAIT_OP_ALL_E_MASK)
#define	E2K_WAIT_ALL		E2K_WAIT(E2K_WAIT_OP_ALL_MASK)

#endif /* !(_E2K_HEAD_H) */
