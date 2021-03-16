/*
 * E2K ISET X86 emulation page table structure and common definitions.
 *
 * Copyright 2017 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _ASM_E2K_KVM_PGTABLE_X86_H
#define _ASM_E2K_KVM_PGTABLE_X86_H

/*
 * This file contains the functions and defines necessary to modify and
 * use the E2K ISET V1-V5 page tables.
 * NOTE: E2K has four levels of page tables.
 */

#include <linux/types.h>
#include <asm/pgtable_types.h>


/* max. number of physical address bits (architected) */
#define MAX_PHYS_BITS_X86_32	32
#define MAX_PHYS_BITS_X86_64	48

/* virtual & physical page definitions */
#define	PAGE_SHIFT_X86		12
#define	PAGE_SIZE_X86		(1ULL << PAGE_SHIFT_X86)

#ifndef __ASSEMBLY__

/*
 * PTE format
 */

#define _PAGE_BIT_PRESENT_X86	0	/* is present */
#define _PAGE_W_BIT_X86		1	/* bit # of Writable */
#define _PAGE_BIT_USER_X86	2	/* userspace addressable */
#define _PAGE_BIT_PWT_X86	3	/* page write through */
#define _PAGE_BIT_PCD_X86	4	/* page cache disabled */
#define _PAGE_BIT_ACCESSED_X86	5	/* was accessed (raised by CPU) */
#define _PAGE_BIT_DIRTY_X86	6	/* was written to (raised by CPU) */
#define _PAGE_BIT_PSE_X86	7	/* 4 MB (or 2MB) page */
#define _PAGE_BIT_PAT_X86	7	/* on 4KB pages */
#define _PAGE_BIT_GLOBAL_X86	8	/* Global TLB entry */
#define _PAGE_BIT_PAT_LARGE_X86	12	/* On 2MB or 1GB pages */
#define	_PAGE_PFN_SHIFT_X86	12	/* shift of PFN field */
#define _PAGE_BIT_NX_X86	63	/* No execute: only valid after */
					/* cpuid check */

#define _PAGE_P_X86		(1ULL << _PAGE_BIT_PRESENT_X86)
#define _PAGE_W_X86		(1ULL << _PAGE_W_BIT_X86)
#define _PAGE_USER_X86		(1ULL << _PAGE_BIT_USER_X86)
#define _PAGE_PWT_X86		(1ULL << _PAGE_BIT_PWT_X86)
#define _PAGE_PCD_X86		(1ULL << _PAGE_BIT_PCD_X86)
#define _PAGE_A_X86		(1ULL << _PAGE_BIT_ACCESSED_X86)
#define _PAGE_D_X86		(1ULL << _PAGE_BIT_DIRTY_X86)
#define _PAGE_PSE_X86		(1ULL << _PAGE_BIT_PSE_X86)
#define _PAGE_PAT_X86		(1ULL << _PAGE_BIT_PAT_X86)
#define _PAGE_G_X86		(1ULL << _PAGE_BIT_GLOBAL_X86)
#define _PAGE_PAT_LARGE_X86	(1ULL << _PAGE_BIT_PAT_LARGE_X86)
#define _PAGE_NX_X86_32		(0ULL)	/* has not such protection */
#define _PAGE_NX_X86_PAE	(1ULL << _PAGE_BIT_NX_X86)
#define _PAGE_NX_X86_64		(1ULL << _PAGE_BIT_NX_X86)

#define _PAGE_PFN_X86_32	/* 0x0000_0000_ffff_f000 */ \
		((((1ULL << MAX_PHYS_BITS_X86_32) - 1) >> \
						PAGE_SHIFT_X86) << \
							_PAGE_PFN_SHIFT_X86)
#define _PAGE_PFN_X86_64	/* 0x0000_ffff_ffff_f000 */ \
		((((1ULL << MAX_PHYS_BITS_X86_64) - 1) >> \
						PAGE_SHIFT_X86) << \
							_PAGE_PFN_SHIFT_X86)

/* Page table entries format */
typedef u32	pt_element_x86_32_t;
typedef u64	pt_element_x86_64_t;

#define	X86_PTE_LEVEL_NUM	1	/* level number of native pte */
#define	X86_32_PGD_LEVEL_NUM	2	/* level number of pgd for 32 bits */
					/* physical & virtual addresses mode */
#define	X86_PAE_PGD_LEVEL_NUM	3	/* level number of pgd for 48 bits */
					/* physical & 32 bits virtual */
					/* addresses mode */
#define	X86_64_PGD_LEVEL_NUM	4	/* level number of pgd for 48 bits */
					/* physical & 48 bits virtual */
					/* addresses mode */
#define	X86_PDPE_LEVEL_NUM	3	/* pgd for PAE mode */
#define	X86_DIRECTORY_LEVEL_NUM	2	/* from this level starts direcrory */
					/* levels of PT */

#define	MAX_HUGE_PAGES_LEVEL_X86_32	X86_32_PGD_LEVEL_NUM
#define	MAX_HUGE_PAGES_LEVEL_X86_PAE	(X86_PAE_PGD_LEVEL_NUM - 1)
#define	MAX_HUGE_PAGES_LEVEL_X86_64	MAX_HUGE_PAGES_LEVEL

/* one page table occupies on 4K page */
#define	PT_ENT_SHIFT_X86_32	2	/* 4 bytes, 2 bits */
#define	PT_ENT_SHIFT_X86_64	3	/* 8 bytes, 3 bits */
#define	PT_ENT_BITS_X86_32	(PAGE_SHIFT_X86 - PT_ENT_SHIFT_X86_32)
#define	PT_ENT_BITS_X86_64	(PAGE_SHIFT_X86 - PT_ENT_SHIFT_X86_64)
#define	PT_ENT_PER_PAGE_X86_32	(1 << PT_ENT_BITS_X86_32)
#define	PT_ENT_PER_PAGE_X86_64	(1 << PT_ENT_BITS_X86_64)

#endif	/* ! __ASSEMBLY__ */

#endif /* ! _ASM_E2K_KVM_PGTABLE_X86_H */
