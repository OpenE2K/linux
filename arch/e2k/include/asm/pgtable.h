/* $Id: pgtable.h,v 1.79 2009/10/13 16:45:06 kravtsunov_e Exp $
 * pgtable.h: E2K page table operations.
 *
 * Copyright 2001 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _E2K_PGTABLE_H
#define _E2K_PGTABLE_H

/*
 * This file contains the functions and defines necessary to modify and
 * use the E2K page tables.
 * NOTE: E2K has four levels of page tables, while Linux assumes that
 * there are three levels of page tables.
 */

#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/swap.h>

#include <asm/page.h>
#include <asm/system.h>
#include <asm/cpu_regs_access.h>
#include <asm/head.h>
#include <asm/bitops.h>
#include <asm/boot_head.h>
#include <asm/machdep.h>
#include <asm/secondary_space.h>
#include <asm/mmu_regs_access.h>

#undef	DEBUG_PT_MODE
#undef	DebugPT
#define	DEBUG_PT_MODE		0	/* page table */
#define DebugPT(...)		DebugPrint(DEBUG_PT_MODE ,##__VA_ARGS__)

#undef	DEBUG_SWAP_MODE
#undef	DebugSWAP
#define	DEBUG_SWAP_MODE		0
#define DebugSWAP(...)		DebugPrint(DEBUG_SWAP_MODE ,##__VA_ARGS__)

#define E2K_MAX_PHYS_BITS	40	/* max. number of physical address */
					/* bits (architected) */

/*
 * remap a physical page `pfn' of size `size' with page protection `prot'
 * into virtual address `from'
 */
#define io_remap_pfn_range(vma, vaddr, pfn, size, prot)		\
		remap_pfn_range(vma, vaddr, pfn, size, prot)

#define MK_IOSPACE_PFN(space, pfn)	(pfn)
#define GET_IOSPACE(pfn)		0
#define GET_PFN(pfn)			(pfn)

#ifndef __ASSEMBLY__

/*
 * Definitions for zero (root) level:
 *
 * PGDIR_SHIFT determines what a root-level page table entry
 * can map:
 *		pages of first-level page table entries
 *
 * Cannot use the top 0xffff ff00 0000 0000 - 0xffff ffff ffff ffff addresses
 * because virtual page table lives there.
 */
#define PGDIR_SHIFT		(PAGE_SHIFT + 3 * (PAGE_SHIFT-3))
#define PGDIR_SIZE		(1UL << PGDIR_SHIFT)
#define PGDIR_MASK		(~(PGDIR_SIZE-1))
#define PTRS_PER_PGD		(1UL << (PAGE_SHIFT-3))
#define	PGD_TABLE_SIZE		(PTRS_PER_PGD * sizeof(pgd_t))
#define USER_PTRS_PER_PGD	(TASK_SIZE / PGDIR_SIZE)
#define FIRST_USER_ADDRESS	0

/*
 * Definitions for upper level:
 *
 * PUD_SHIFT determines the size of the area a first level page tables
 * can map:
 *		pages of second-level page table entries
 */
#define PUD_SHIFT		(PAGE_SHIFT + 2 * (PAGE_SHIFT-3))
#define PUD_SIZE		(1UL << PUD_SHIFT)
#define PUD_MASK		(~(PUD_SIZE-1))
#define PTRS_PER_PUD		(1UL << (PAGE_SHIFT-3))
#define	PUD_TABLE_SIZE		(PTRS_PER_PUD * sizeof(pud_t))

/*
 * Definitions for middle level:
 *
 * PMD_SHIFT determines the size of the area a first level page tables
 * can map:
 *		pages of third-level page table entries
 */
#define PMD_SHIFT		(PAGE_SHIFT + 1 * (PAGE_SHIFT-3))
#define PMD_SIZE		(1UL << PMD_SHIFT)
#define PMD_MASK		(~(PMD_SIZE-1))
#define PTRS_PER_PMD		(1UL << (PAGE_SHIFT-3))
#define	PMD_TABLE_SIZE		(PTRS_PER_PMD * sizeof(pmd_t))
#define PMDS_PER_LARGE_PAGE	\
		((E2K_LARGE_PAGE_SIZE == E2K_4M_PAGE_SIZE) ? 2 : 1)

/*
 * Definitions for third level:
 *
 * PTE - Entries per user pages.
 */
#define PTE_SHIFT		(PAGE_SHIFT)		/* PAGE_SHIFT */
#define PTE_SIZE		(1UL << PTE_SHIFT)	/* PAGE_SIZE */
#define PTE_MASK		(~(PTE_SIZE-1))		/* PAGE_MASK */
#define PTRS_PER_PTE		(1UL << (PAGE_SHIFT-3))
#define	PTE_TABLE_SIZE		(PTRS_PER_PTE * sizeof(pte_t))

#define VMALLOC_START		(E2K_KERNEL_IMAGE_AREA_BASE + 0x20000000000UL)
				/* 0x0000 e400 0000 0000 */
#define VMALLOC_END		(VMALLOC_START + 0x10000000000UL)
				/* 0x0000 e500 0000 0000 */
#define EARLY_IO_VMALLOC_START	(VMALLOC_END)
				/* 0x0000 e500 0000 0000 */
#define EARLY_IO_VMALLOC_END	(EARLY_IO_VMALLOC_START + 0x100000000UL)
				/* 0x0000 e501 0000 0000 */

/*
 * The module space starts from end of resident kernel image and
 * both areas should be within 2 ** 30 bits of the virtual addresses.
 */
#define MODULE_START	E2K_MODULE_START	/* 0x0000 e200 0xxx x000 */
#define MODULE_END	E2K_MODULE_END		/* 0x0000 e200 4000 0000 */

/*
 * PTE format
 */

#define __HAVE_ARCH_PTE_SPECIAL

#define _PAGE_W_BIT		1		/* bit # of Writable */
#define	_PAGE_CD1_BIT		4		/* right bit of Cache disable */
#define	_PAGE_CD2_BIT		9		/* left bit of Cache disable */
#define _PAGE_A_HW_BIT		5		/* bit # of Accessed Page */
#define	_PAGE_D_BIT		6		/* bit # of Page Dirty */
#define	_PAGE_HUGE_BIT		7		/* bit # of Page Size */
#define _PAGE_AVAIL_BIT		11
#define	_PAGE_PFN_SHIFT		12		/* shift of PFN field */
#define	_PAGE_CU_BITS		48		/* bits # of Compilation Unit */


#define _PAGE_P		0x0000000000000001ULL	/* Page Present bit */
#define _PAGE_W		0x0000000000000002ULL	/* Writable (0 - only read) */
#define _PAGE_UU2	0x0000000000000004ULL	/* unused bit # 2 */
#define _PAGE_PWT	0x0000000000000008ULL	/* Write Through */
#define _PAGE_CD1	(1UL << _PAGE_CD1_BIT)	/* 0x0000000000000010 */
						/* Cache disable (right bit) */
#define _PAGE_A_HW	(1UL << _PAGE_A_HW_BIT)	/* Accessed Page */
#define _PAGE_D		(1UL << _PAGE_D_BIT)	/* Page Dirty */
#define _PAGE_HUGE	0x0000000000000080ULL	/* Page Size */
#define _PAGE_G		0x0000000000000100ULL	/* Global Page */
#define _PAGE_CD2	(1UL << _PAGE_CD2_BIT)	/* 0x0000000000000200 */
						/* Cache disable (left bit) */
#define _PAGE_NWA	0x0000000000000400ULL	/* Prohibit address writing */
#define _PAGE_AVAIL	(1UL << _PAGE_AVAIL_BIT)
#define _PAGE_PFN	0x000000fffffff000ULL	/* Physical Page Number */
#define _PAGE_VALID	0x0000010000000000ULL	/* Valid Page */
#define _PAGE_PV	0x0000020000000000ULL	/* PriVileged Page */
#define _PAGE_INT_PR	0x0000040000000000ULL	/* Integer address access */
						/* Protection */
#define _PAGE_NON_EX	0x0000080000000000ULL	/* Non Executable Page */
#define _PAGE_RES	0x0000f00000000000ULL	/* Reserved bits */
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
#define	_PAGE_SEC_MAP	0x0000200000000000ULL	/* Secondary space mapping */
						/* Software only bit */
#endif
#define _PAGE_A_SW	(1UL << _PAGE_A_SW_BIT)	/* Accessed Page
						   (software emulation) */
#define _PAGE_C_UNIT	0xffff000000000000ULL	/* Compilation Unit */


/* #76626 - hardware access bit should always be set. So we do not
 * touch it and use software bit for things like pte_mkyoung(). */
#if !defined(CONFIG_BOOT_E2K) && !defined(E2K_P2V) && \
		(defined CONFIG_CPU_E3M || \
		 defined CONFIG_CPU_ES2)
# define _PAGE_A_SW_BIT		47		/* bit # of Accessed Page
						   (software emulated) */
# define _PAGE_A_BIT	(cpu_has(CPU_HWBUG_PAGE_A) ? \
			 _PAGE_A_SW_BIT : _PAGE_A_HW_BIT)
#else
# define _PAGE_A_SW_BIT	_PAGE_A_HW_BIT
# define _PAGE_A_BIT	_PAGE_A_HW_BIT
#endif
#define _PAGE_A		(1UL << _PAGE_A_BIT)	/* Accessed Page */


#define	_PAGE_SPECIAL	_PAGE_AVAIL
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
/* _PAGE_SPECIAL is used for pte's and _PAGE_SPLITTING is used for pmd's,
 * so there is no conflict. */
# define _PAGE_SPLITTING_BIT	_PAGE_AVAIL_BIT	/* For large pages only */
# define _PAGE_SPLITTING	_PAGE_AVAIL /* == _PAGE_SPECIAL */
#endif


#define _PAGE_CD_MASK	(_PAGE_CD1 | _PAGE_CD2)	/* Cache disable flags */
#define	_PAGE_CD_VAL(x)		((x & 0x1) << _PAGE_CD1_BIT | \
				 (x & 0x2) << (_PAGE_CD2_BIT - 1))
#define _PAGE_CD_D1_DIS	_PAGE_CD_VAL(1UL)	/* DCACHE1 disabled */
#define _PAGE_CD_D_DIS	_PAGE_CD_VAL(2UL)	/* DCACHE1, DCACHE2 disabled */
#define _PAGE_CD_DIS	_PAGE_CD_VAL(3UL)	/* DCACHE1, DCACHE2, ECACHE */
						/* disabled */

#define	_PAGE_PADDR_TO_PFN(phys_addr)	(((e2k_addr_t)phys_addr) & _PAGE_PFN)
						/* convert physical address */
						/* to page frame number */
						/* for PTE */
#define	_PAGE_PFN_TO_PADDR(pte_val)	(((e2k_addr_t)(pte_val) & _PAGE_PFN))
						/* convert the page frame */
						/* number from PTE to */
						/* physical address */
#define	_PAGE_INDEX_TO_CUNIT(index)	(((u64)(index) << _PAGE_CU_BITS) & \
							_PAGE_C_UNIT)
#define	_PAGE_INDEX_FROM_CUNIT(prot)	(((prot) & _PAGE_C_UNIT) \
							>> _PAGE_CU_BITS)
#define	_PAGE_PRESENT		_PAGE_P
#define _PFN_MASK		_PAGE_PFN
#define _PAGE_CHG_MASK	(_PFN_MASK | _PAGE_A_HW | _PAGE_A | _PAGE_D | \
			 _PAGE_SPECIAL | _PAGE_CD1 | _PAGE_CD2 | _PAGE_PWT)
#define _HPAGE_CHG_MASK		(_PAGE_CHG_MASK | _PAGE_HUGE)
#define _PROT_REDUCE_MASK	(_PAGE_P | _PAGE_W | _PAGE_A_HW | _PAGE_A | \
				 _PAGE_D | _PAGE_VALID | _PAGE_G | \
				 _PAGE_CD_MASK | _PAGE_PWT)
#define _PROT_RESTRICT_MASK	(_PAGE_PV | _PAGE_NON_EX | _PAGE_INT_PR)

#define _PAGE_KERNEL_RX_NOT_GLOB	(_PAGE_P | _PAGE_VALID | \
					 _PAGE_PV | _PAGE_A_HW)
#define _PAGE_KERNEL_RO_NOT_GLOB	(_PAGE_P | _PAGE_VALID | \
					 _PAGE_PV | _PAGE_A_HW | _PAGE_NON_EX)
#define _PAGE_KERNEL_RWX_NOT_GLOB	(_PAGE_KERNEL_RX_NOT_GLOB | \
					 _PAGE_W | _PAGE_D)
#define _PAGE_KERNEL_RW_NOT_GLOB	(_PAGE_KERNEL_RWX_NOT_GLOB | \
					 _PAGE_NON_EX)
#ifdef	CONFIG_GLOBAL_CONTEXT
#define _PAGE_KERNEL_RX		(_PAGE_KERNEL_RX_NOT_GLOB | _PAGE_G)
#define _PAGE_KERNEL_RO		(_PAGE_KERNEL_RO_NOT_GLOB | _PAGE_G)
#define _PAGE_KERNEL_RWX	(_PAGE_KERNEL_RWX_NOT_GLOB | _PAGE_G)
#define _PAGE_KERNEL_RW		(_PAGE_KERNEL_RW_NOT_GLOB | _PAGE_G)
#else	/* ! CONFIG_GLOBAL_CONTEXT */
#define _PAGE_KERNEL_RX		_PAGE_KERNEL_RX_NOT_GLOB
#define _PAGE_KERNEL_RO		_PAGE_KERNEL_RO_NOT_GLOB
#define _PAGE_KERNEL_RWX	_PAGE_KERNEL_RWX_NOT_GLOB
#define _PAGE_KERNEL_RW		_PAGE_KERNEL_RW_NOT_GLOB
#endif	/* CONFIG_GLOBAL_CONTEXT */

#define _PAGE_KERNEL		_PAGE_KERNEL_RW
#define _PAGE_KERNEL_IMAGE	_PAGE_KERNEL_RX
#define _PAGE_KERNEL_MODULE	_PAGE_KERNEL_RWX
#define _PAGE_KERNEL_PT		_PAGE_KERNEL
#define _PAGE_USER_PT		_PAGE_KERNEL_RW_NOT_GLOB
#define _PAGE_KERNEL_PTE	_PAGE_KERNEL_PT
#define _PAGE_KERNEL_PMD	_PAGE_KERNEL_PT
#define _PAGE_KERNEL_PUD	_PAGE_KERNEL_PT
#define _PAGE_USER_PTE		_PAGE_USER_PT
#define _PAGE_USER_PMD		_PAGE_USER_PT
#define _PAGE_USER_PUD		_PAGE_USER_PT

#define _PAGE_IO_MAP_CACHE	_PAGE_KERNEL_RW
#define _PAGE_IO_MAP		(_PAGE_IO_MAP_CACHE | _PAGE_CD_DIS | _PAGE_PWT)
#define _PAGE_IO_PORTS		_PAGE_IO_MAP

#define _PAGE_KERNEL_SWITCHING_IMAGE	(_PAGE_KERNEL_RX_NOT_GLOB | _PAGE_PWT)

#define _PAGE_USER		(_PAGE_P | _PAGE_VALID | \
					_PAGE_W | _PAGE_D | _PAGE_NON_EX)

#define PAGE_KERNEL		__pgprot(_PAGE_KERNEL)
#define	PAGE_KERNEL_LARGE	__pgprot(_PAGE_KERNEL | _PAGE_HUGE)
#define	PAGE_KERNEL_PTE		__pgprot(_PAGE_KERNEL_PTE)
#define	PAGE_KERNEL_PMD		__pgprot(_PAGE_KERNEL_PMD)
#define	PAGE_KERNEL_PUD		__pgprot(_PAGE_KERNEL_PUD)
#define	PAGE_USER_PTE		__pgprot(_PAGE_USER_PTE)
#define	PAGE_USER_PMD		__pgprot(_PAGE_USER_PMD)
#define	PAGE_USER_PUD		__pgprot(_PAGE_USER_PUD)

#define	PAGE_KERNEL_NOCACHE	PAGE_IO_MAP

#define PAGE_USER		__pgprot(_PAGE_USER)

#define PAGE_KERNEL_TEXT	__pgprot(_PAGE_KERNEL_IMAGE)
#ifdef	CONFIG_KERNEL_CODE_CONTEXT
#define PAGE_KERNEL_PROT_TEXT	\
			__pgprot(_PAGE_KERNEL_IMAGE | \
				_PAGE_INDEX_TO_CUNIT(KERNEL_CODES_INDEX))
#endif	/* CONFIG_KERNEL_CODE_CONTEXT */

#define PAGE_KERNEL_DATA	__pgprot(_PAGE_KERNEL_IMAGE | _PAGE_W | \
					_PAGE_NON_EX)
#define PAGE_KERNEL_MODULE	__pgprot(_PAGE_KERNEL_MODULE)
#define PAGE_KERNEL_PS		__pgprot(_PAGE_KERNEL | _PAGE_NON_EX)
#define PAGE_KERNEL_PCS		__pgprot(_PAGE_KERNEL | _PAGE_NON_EX)
#define PAGE_KERNEL_STACK	__pgprot(_PAGE_KERNEL | _PAGE_NON_EX)

#define PAGE_TAG_MEMORY		__pgprot(_PAGE_KERNEL_RW_NOT_GLOB)

#define PAGE_BOOTINFO		__pgprot(_PAGE_KERNEL_IMAGE | _PAGE_NON_EX)

#define PAGE_INITRD		__pgprot(_PAGE_KERNEL_IMAGE | _PAGE_NON_EX)

#define PAGE_MPT		__pgprot(_PAGE_KERNEL_IMAGE | _PAGE_NON_EX)

#define PAGE_KERNEL_NAMETAB	__pgprot(_PAGE_KERNEL_IMAGE | _PAGE_NON_EX)

#define PAGE_MAPPED_PHYS_MEM	__pgprot(_PAGE_KERNEL)

#define PAGE_CNTP_MAPPED_MEM	__pgprot(_PAGE_KERNEL_IMAGE | _PAGE_NON_EX)

#define PAGE_X86_IO_PORTS	__pgprot(_PAGE_IO_PORTS)

#define PAGE_IO_MAP		__pgprot(_PAGE_IO_MAP)

#define	PAGE_KERNEL_SWITCHING_TEXT	__pgprot(_PAGE_KERNEL_SWITCHING_IMAGE)
#define	PAGE_KERNEL_SWITCHING_DATA	__pgprot(_PAGE_KERNEL_SWITCHING_IMAGE \
						| _PAGE_W | _PAGE_NON_EX)
#define	PAGE_KERNEL_SWITCHING_US_STACK	__pgprot(_PAGE_KERNEL_RW_NOT_GLOB | \
						 _PAGE_PWT)

#define PAGE_SHARED		__pgprot(_PAGE_PRESENT | _PAGE_VALID | \
					 _PAGE_A_HW | _PAGE_A_SW | _PAGE_W | \
					 _PAGE_NON_EX)
#define PAGE_SHARED_EX		__pgprot(_PAGE_PRESENT | _PAGE_VALID | \
					 _PAGE_A_HW | _PAGE_A_SW | _PAGE_W)
#define	PAGE_COPY_NEX		__pgprot(_PAGE_PRESENT | _PAGE_VALID | \
					 _PAGE_A_HW | _PAGE_A_SW | _PAGE_NON_EX)
#define	PAGE_COPY_EX		__pgprot(_PAGE_PRESENT | _PAGE_VALID | \
					 _PAGE_A_HW | _PAGE_A_SW)

#define	PAGE_COPY		PAGE_COPY_NEX

#define PAGE_READONLY		__pgprot(_PAGE_PRESENT | _PAGE_VALID | \
					 _PAGE_A_HW | _PAGE_A_SW | _PAGE_NON_EX)
#define PAGE_EXECUTABLE		__pgprot(_PAGE_PRESENT | _PAGE_VALID | \
					 _PAGE_A_HW | _PAGE_A_SW)

#define PAGE_NONE		__pgprot((_PAGE_PRESENT | _PAGE_PV | \
					 _PAGE_A_HW | _PAGE_A_SW | \
					 _PAGE_NON_EX) & (~_PAGE_VALID))

#define PAGE_INT_PR		__pgprot(_PAGE_INT_PR)

/*
 * Next come the mappings that determine how mmap() protection bits
 * (PROT_EXEC, PROT_READ, PROT_WRITE, PROT_NONE) get implemented.  The
 * _P version gets used for a private shared memory segment, the _S
 * version gets used for a shared memory segment with MAP_SHARED on.
 * In a private shared memory segment, we do a copy-on-write if a task
 * attempts to write to the page.
 */
	/* xwr */
#define __P000	PAGE_NONE
#define __P001	PAGE_READONLY
#define __P010	PAGE_COPY_NEX
#define __P011	PAGE_COPY_NEX
#define __P100	PAGE_EXECUTABLE
#define __P101	PAGE_EXECUTABLE
#define __P110	PAGE_COPY_EX
#define __P111	PAGE_COPY_EX

#define __S000	PAGE_NONE
#define __S001	PAGE_READONLY
#define __S010	PAGE_SHARED
#define __S011	PAGE_SHARED
#define __S100	PAGE_EXECUTABLE
#define __S101	PAGE_EXECUTABLE
#define __S110	PAGE_SHARED_EX
#define __S111	PAGE_SHARED_EX

#define pgd_ERROR(e)	printk("%s:%d: bad pgd 0x%016lx.\n", \
				__FILE__, __LINE__, pgd_val(e))
#define pud_ERROR(e)	printk("%s:%d: bad pud 0x%016lx.\n", \
				__FILE__, __LINE__, pud_val(e))
#define pmd_ERROR(e)	printk("%s:%d: bad pmd 0x%016lx.\n", \
				__FILE__, __LINE__, pmd_val(e))
#define pte_ERROR(e)	printk("%s:%d: bad pte 0x%016lx.\n", \
				__FILE__, __LINE__, pte_val(e))

/*
 * Some definitions to translate between mem_map, PTEs, and page
 * addresses:
 */

extern unsigned long pfn_base;

/*
 * ZERO_PAGE is a global shared page that is always zero: used
 * for zero-mapped memory areas etc..
 */
extern unsigned long	empty_zero_page[PAGE_SIZE/sizeof(unsigned long)];
extern struct page	*zeroed_page;
extern u64		zero_page_nid_to_pfn[MAX_NUMNODES];
extern struct page	*zero_page_nid_to_page[MAX_NUMNODES];

#define ZERO_PAGE(vaddr) zeroed_page

#define is_zero_pfn is_zero_pfn
static inline int is_zero_pfn(unsigned long pfn)
{
	int node;

	for_each_node_has_dup_kernel(node)
		if (zero_page_nid_to_pfn[node] == pfn)
			return 1;

	return 0;
}

#define my_zero_pfn my_zero_pfn
static inline u64 my_zero_pfn(unsigned long addr)
{
	u64 pfn = 0;
	int node = numa_node_id();

	if (node_has_dup_kernel(node)) {
		pfn = zero_page_nid_to_pfn[node];
	} else {
		for_each_node_has_dup_kernel(node) {
			pfn = zero_page_nid_to_pfn[node];
			break;
		}
	}

	return pfn;
}

static inline int is_zero_page(struct page *page)
{
	int node;

	for_each_node_has_dup_kernel(node)
		if (zero_page_nid_to_page[node] == page)
			return 1;

	return 0;
}


/*
 * The defines and routines to manage and access the four-level
 * page table.
 */

/*
 * On some architectures, special things need to be done when setting
 * the PTE in a page table.  Nothing special needs to be on E2K.
 */
#define set_pte(ptep, pteval)			(*(ptep) = (pteval))
#define set_pmd(pmdp, pmdval)			(*(pmdp) = (pmdval))

#ifndef CONFIG_SECONDARY_SPACE_SUPPORT

#define set_pte_at(mm, addr, ptep, pteval)	set_pte(ptep,pteval)

#else

#define set_pte_at(mm, addr, ptep, pteval) \
({ \
	set_pte(ptep, pteval); \
	if (TASK_IS_BINCO(current)) \
		set_pte_at_binco(addr, ptep, pteval); \
})
extern void set_pte_at_binco(unsigned long addr, pte_t *ptep, pte_t pteval);
#endif	/* CONFIG_SECONDARY_SPACE_SUPPORT */

#define set_pmd_at(mm, addr, pmdp, pmdval)	set_pmd(pmdp, pmdval)

/*
 * This takes a physical page address and protection bits to make
 * pte/pmd/pud/pgd
 */
#define mk_pte_phys(phys_addr, pgprot) \
	(__pte(_PAGE_PADDR_TO_PFN(phys_addr) | pgprot_val(pgprot)))
#define mk_pmd_phys(phys_addr, pgprot) \
	(__pmd(_PAGE_PADDR_TO_PFN(phys_addr) | pgprot_val(pgprot)))
#define mk_pud_phys(phys_addr, pgprot) \
	(__pud(_PAGE_PADDR_TO_PFN(phys_addr) | pgprot_val(pgprot)))
#define mk_pgd_phys(phys_addr, pgprot) \
	(__pgd(_PAGE_PADDR_TO_PFN(phys_addr) | pgprot_val(pgprot)))

#define mk_pmd_addr(virt_addr, pgprot) \
	(__pmd(_PAGE_PADDR_TO_PFN(__pa(virt_addr)) | pgprot_val(pgprot)))
#define mk_pud_addr(virt_addr, pgprot) \
	(__pud(_PAGE_PADDR_TO_PFN(__pa(virt_addr)) | pgprot_val(pgprot)))
#define mk_pgd_addr(virt_addr, pgprot) \
	(__pgd(_PAGE_PADDR_TO_PFN(__pa(virt_addr)) | pgprot_val(pgprot)))

/*
 * Conversion functions: convert page frame number (pfn) and
 * a protection value to a page table entry (pte).
 */
#define pfn_pte(pfn, pgprot)	mk_pte_phys((pfn) << PAGE_SHIFT, pgprot)
#define pfn_pmd(pfn, pgprot)	mk_pmd_phys((pfn) << PAGE_SHIFT, pgprot)

/*
 * Macro to mark a page protection value as "uncacheable".
 */
#define pgprot_noncached(prot)		(__pgprot(pgprot_val(prot) | \
						_PAGE_CD_DIS | _PAGE_PWT))

#define pgprot_writecombine(prot)	(__pgprot(pgprot_val(prot) | \
						_PAGE_CD_DIS))

/*
 * Extract pfn from pte.
 */
#define pte_pfn(pte)	(_PAGE_PFN_TO_PADDR(pte_val(pte)) >> PAGE_SHIFT)
#define pmd_pfn(pmd)	(_PAGE_PFN_TO_PADDR(pmd_val(pmd)) >> PAGE_SHIFT)

#define mk_pte(page, pgprot)	pfn_pte(page_to_pfn(page), (pgprot))
#define mk_pmd(page, pgprot)	pfn_pmd(page_to_pfn(page), (pgprot))

#define mk_clone_pte(page, pte)	pfn_pte(page_to_pfn(page), \
				__pgprot(pte_val(pte) & ~_PFN_MASK))
#define mk_not_present_pte(pgprot)		\
				__pte(pgprot_val(pgprot) & ~_PAGE_PRESENT)
#define mk_pte_pgprot(pte, pgprot)		\
				__pte(pte_val(pte) | pgprot_val(pgprot))
#define page_pte_prot(page, prot)	mk_pte(page, prot)
#define page_pte(page)			page_pte_prot(page, __pgprot(0))

#define pgprot_modify_mask(old_prot, newprot_val, prot_mask) \
		(__pgprot(((pgprot_val(old_prot) & ~(prot_mask)) | \
		((newprot_val) & (prot_mask)))))

#define pgprot_large_size_set(prot) \
		__pgprot(pgprot_val(prot) | _PAGE_HUGE)
#define pgprot_small_size_set(prot) \
		__pgprot(pgprot_val(prot) & ~_PAGE_HUGE)
#define pgprot_present_flag_set(prot) \
		pgprot_modify_mask(prot, _PAGE_P, _PAGE_P)
#define pgprot_present_flag_reset(prot) \
		pgprot_modify_mask(prot, 0UL, _PAGE_P | _PFN_MASK)
#define _pgprot_reduce(src_prot_val, reduced_prot_val) \
		(((src_prot_val) & ~(_PROT_REDUCE_MASK)) | \
			(((src_prot_val) & (_PROT_REDUCE_MASK)) | \
			((reduced_prot_val) & (_PROT_REDUCE_MASK))))
#define _pgprot_restrict(src_prot_val, restricted_prot_val) \
		(((src_prot_val) & ~(_PROT_RESTRICT_MASK)) | \
			(((src_prot_val) & (_PROT_RESTRICT_MASK)) & \
			((restricted_prot_val) & (_PROT_RESTRICT_MASK))))
#define pgprot_reduce(src_prot, reduced_prot) \
		(__pgprot(_pgprot_reduce(pgprot_val(src_prot), \
					pgprot_val(reduced_prot))))
#define pgprot_restrict(src_prot, restricted_prot) \
		(__pgprot(_pgprot_restrict(pgprot_val(src_prot), \
					pgprot_val(restricted_prot))))
#define pte_reduce_prot(src_pte, reduced_prot) \
		(__pte(_pgprot_reduce(pte_val(src_pte), \
					pgprot_val(reduced_prot))))
#define pte_restrict_prot(src_pte, restricted_prot) \
		(__pte(_pgprot_restrict(pte_val(src_pte), \
					pgprot_val(restricted_prot))))
#define pgprot_priv(pgprot)		(pgprot_val(pgprot) & _PAGE_PV)

static inline pte_t pte_modify(pte_t pte, pgprot_t newprot)
{
	pteval_t val = pte_val(pte);

	val &= _PAGE_CHG_MASK;
	val |= pgprot_val(newprot) & ~_PAGE_CHG_MASK;

	return __pte(val);
}

static inline pmd_t pmd_modify(pmd_t pmd, pgprot_t newprot)
{
	pmdval_t val = pmd_val(pmd);

	val &= _HPAGE_CHG_MASK;
	val |= pgprot_val(newprot) & ~_HPAGE_CHG_MASK;

	return __pmd(val);
}


#ifndef	CONFIG_MAKE_ALL_PAGES_VALID
#define pte_none(pte)	(!pte_val(pte))
#else
#ifndef CONFIG_SECONDARY_SPACE_SUPPORT
#define pte_none(pte)	((pte_val(pte) & ~_PAGE_VALID) == 0)
#else
#define pte_none(pte)	((pte_val(pte) & ~(_PAGE_VALID | _PAGE_SEC_MAP)) == 0)
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */
#endif	/* CONFIG_MAKE_ALL_PAGES_VALID */

#define pte_valid(pte)			(pte_val(pte) & _PAGE_VALID)
#define pte_present(pte)		(pte_val(pte) & _PAGE_PRESENT)
#define pte_secondary(pte)		(pte_val(pte) & _PAGE_SEC_MAP)
#define pgd_clear_kernel(pgdp)		(pgd_val(*(pgdp)) = 0UL)
#define pud_clear_kernel(pudp)		(pud_val(*(pudp)) = 0UL)
#define pmd_clear_kernel(pmdp)		(pmd_val(*(pmdp)) = 0UL)
#define pte_clear_kernel(ptep)		(pte_val(*(ptep)) = 0UL)
#define pte_clear(mm, addr, ptep)	do { set_pte_at(mm, addr, ptep, __pte(0)); \
					} while (0)
#define pte_priv(pte)			(pte_val(pte) & _PAGE_PV)
#define	pmd_large(pmd)			(pmd_val(pmd) & _PAGE_HUGE)

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static inline int has_transparent_hugepage(void)
{
	return true;
}

#define pmd_mksplitting(pmd)	(__pmd(pmd_val(pmd) | _PAGE_SPLITTING))

#define pmd_trans_splitting(pmd)	(pmd_val(pmd) & _PAGE_SPLITTING)
#define pmd_trans_huge(pmd)		pmd_large(pmd)
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

#define pmd_read(pmd)		(1)
#define pmd_write(pmd)		(pmd_val(pmd) & _PAGE_W)
#define pmd_exec(pmd)		((pmd_val(pmd) & _PAGE_NON_EX) == 0)
#define pmd_dirty(pmd)		((pmd_val(pmd) & _PAGE_D) != 0)
#define pmd_young(pmd)		((pmd_val(pmd) & _PAGE_A) != 0)

#define pmd_wrprotect(pmd)	(__pmd(pmd_val(pmd) & ~_PAGE_W))
#define pmd_mkwrite(pmd)	(__pmd(pmd_val(pmd) | _PAGE_W))
#define pmd_mkexec(pmd)		(__pmd(pmd_val(pmd) & ~_PAGE_NON_EX))
#define pmd_mkold(pmd)		(__pmd(pmd_val(pmd) & ~_PAGE_A))
#define pmd_mkyoung(pmd)	(__pmd(pmd_val(pmd) | _PAGE_A))
#define pmd_mkclean(pmd)	(__pmd(pmd_val(pmd) & ~_PAGE_D))
#define pmd_mkdirty(pmd)	(__pmd(pmd_val(pmd) | _PAGE_D))
#define pmd_mkhuge(pmd)		(__pmd(pmd_val(pmd) | _PAGE_HUGE))
#define pmd_mknotpresent(pmd)	(__pmd(pmd_val(pmd) & ~_PAGE_P))

/* pte_page() returns the 'struct page *' corresponding to the PTE: */
#define pte_page(x)			pfn_to_page(pte_pfn(x))

#define	boot_pte_page(pte)		\
		(e2k_addr_t)boot_va(_PAGE_PFN_TO_PADDR(pte_val(pte)))

#define pmd_set_k(pmdp, ptep)		(*(pmdp) = mk_pmd_addr(ptep, \
							PAGE_KERNEL_PTE))
#define pmd_set_u(pmdp, ptep)		(*(pmdp) = mk_pmd_addr(ptep, \
							PAGE_USER_PTE))
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
#define pmd_set_s(pmdp, ptep)		(*(pmdp) = mk_pmd_addr(ptep, \
							PAGE_SECONDARY_PT))
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */

#ifndef	CONFIG_MAKE_ALL_PAGES_VALID
#define pmd_none(pmd)	(!pmd_val(pmd))
#else
#ifndef CONFIG_SECONDARY_SPACE_SUPPORT
#define pmd_none(pmd)	((pmd_val(pmd) & ~(_PAGE_HUGE | _PAGE_VALID)) == 0)
#else
#define pmd_none(pmd)	((pmd_val(pmd) & ~(_PAGE_SEC_MAP | _PAGE_HUGE | \
							_PAGE_VALID)) == 0)
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */
#endif /* CONFIG_MAKE_ALL_PAGES_VALID */

#define pmd_bad_kernel(pmd)						\
({									\
	unsigned long pmd_value = pmd_val(pmd);				\
	int res = 0;							\
	if (!pmd_none(pmd) && !pmd_large(pmd)) {			\
		pmd_value &= ~(_PFN_MASK | _PAGE_SEC_MAP);		\
		if (pmd_value != _PAGE_KERNEL_PTE)			\
			res = 1;					\
	}								\
	res;								\
})
#define pmd_bad_user(pmd)						\
({									\
	unsigned long pmd_value = pmd_val(pmd);				\
	int res = 0;							\
	if (!pmd_none(pmd) && !pmd_large(pmd)) {			\
		pmd_value &= ~(_PFN_MASK | _PAGE_SEC_MAP);		\
		if (pmd_value != _PAGE_USER_PTE)			\
			res = 1;					\
	}								\
	res;								\
})
#define pmd_bad(pmd)		(pmd_bad_kernel(pmd) && pmd_bad_user(pmd))
#define pmd_present(pmd)	(pmd_val(pmd) & _PAGE_PRESENT)
#define pmd_secondary(pmd)	(pmd_val(pmd) & _PAGE_SEC_MAP)
#define	is_pmd_secondary_1st(pmdp)	\
			(((e2k_addr_t)(pmdp) & (sizeof (*(pmdp)))) == 0)
#define	get_pmd_secondary_1st(pmdp)	\
			((is_pmd_secondary_1st(pmdp)) ? (pmdp) : ((pmdp) - 1))

#ifndef CONFIG_SECONDARY_SPACE_SUPPORT
#define pmd_clear(pmdp)		(pmd_val(*(pmdp)) = 0UL)
#define pmd_page(pmd)		phys_to_page(_PAGE_PFN_TO_PADDR(pmd_val(pmd)))
#else
extern	inline void pmd_clear_sec(pmd_t *pmd);
/*
 * For secondary space pmd we don't real clear pmd (and free pte),
 * because we use set of "compound pages" for such pmds.
 * Instead we mark the pmd entry as "frozen".
 */
#define pmd_clear(pmdp)			if (!pmd_secondary(*(pmdp)) ||  \
					    IS_UPT_E3S) {		\
						pmd_val(*(pmdp)) = 0UL;	\
					} else {			\
						pmd_clear_sec(pmdp);	\
					}
/*
 * To get (struct page *) address with TBL_SEC_BIT
 */
#define __pmd_page(pmd)	phys_to_page(_PAGE_PFN_TO_PADDR(pmd_val(pmd)))

#define pmd_page(pmd)							\
({									\
	struct page *res = __pmd_page(pmd);				\
	if (!IS_UPT_E3S)						\
		res = (struct page *) mark_sec(pmd_val(pmd), res);	\
	res;								\
})
#define	pmd_head_page(pmdp)						\
({									\
	struct page *res;						\
	if (IS_UPT_E3S || !pmd_secondary(*(pmdp)))			\
		res = __pmd_page(*(pmdp));				\
	else {								\
		pmd_t *pmdp_1st = get_pmd_secondary_1st(pmdp);		\
		pmd_t pmd_1st = *pmdp_1st;				\
		res = (struct page *)mark_sec(pmd_val(pmd_1st),		\
						__pmd_page(pmd_1st));	\
	}								\
	res;								\
})
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */



#define pmd_page_kernel(pmd)		\
		((e2k_addr_t) __va(_PAGE_PFN_TO_PADDR(pmd_val(pmd))))

#define boot_pmd_set_k(pmdp, ptep)	(*(pmdp) = mk_pmd_phys(ptep, \
						PAGE_KERNEL_PTE))
#define boot_pmd_set_u(pmdp, ptep)	(*(pmdp) = mk_pmd_phys(ptep, \
						PAGE_USER_PTE))
#define	boot_pmd_page(pmd)		\
		(e2k_addr_t)boot_va(_PAGE_PFN_TO_PADDR(pmd_val(pmd)))

#define pud_set_k(pudp, pmdp)		(*(pudp) = mk_pud_addr(pmdp, \
							PAGE_KERNEL_PMD))
#define pud_set_u(pudp, pmdp)		(*(pudp) = mk_pud_addr(pmdp, \
							PAGE_USER_PMD))
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
#define pud_set_s(pudp, pmdp)		(*(pudp) = mk_pud_addr(pmdp, \
							PAGE_SECONDARY_PT))
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */

#ifndef CONFIG_SECONDARY_SPACE_SUPPORT
#define pud_none(pud)			(pud_val(pud) == 0)
#else
#define pud_none(pud)			((pud_val(pud) & ~_PAGE_SEC_MAP) == 0)
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */

#define pud_bad_kernel(pud)						\
({									\
	unsigned long pud_value;					\
	int res = 0;							\
	if (!pud_none(pud)) {						\
		pud_value = pud_val(pud) &				\
				~(_PFN_MASK | _PAGE_SEC_MAP);		\
		if (pud_value != _PAGE_KERNEL_PMD)			\
			res = 1;					\
	}								\
	res;								\
})
#define pud_bad_user(pud)						\
({									\
	unsigned long pud_value;					\
	int res = 0;							\
	if (!pud_none(pud)) {						\
		pud_value = pud_val(pud) &				\
				~(_PFN_MASK | _PAGE_SEC_MAP);		\
		if (pud_value != _PAGE_USER_PMD)			\
			res = 1;					\
	}								\
	res;								\
})
#define pud_bad(pud)		(pud_bad_kernel(pud) && pud_bad_user(pud))
#define pud_present(pud)	(pud_val(pud) & _PAGE_PRESENT)
#define pud_secondary(pud)	(pud_val(pud) & _PAGE_SEC_MAP)

#ifndef CONFIG_SECONDARY_SPACE_SUPPORT
#define pud_clear(pudp)			(pud_val(*(pudp)) = 0UL)
#define pud_page(pud)			((e2k_addr_t) \
					__va(_PAGE_PFN_TO_PADDR(pud_val(pud))))
#else
extern	inline void pud_clear_sec(pud_t *pudp);
#define pud_clear(pudp)			if (!pud_secondary(*(pudp)) ||	\
					    IS_UPT_E3S) {		\
						pud_val(*(pudp)) = 0UL;	\
					} else ({			\
						pud_clear_sec(pudp);	\
					})

#define pud_page(pud)		((!pud_secondary(pud) || IS_UPT_E3S) ? \
					  ((e2k_addr_t) \
			__va(_PAGE_PFN_TO_PADDR(pud_val(pud)))) : \
					 ((e2k_addr_t)( (u64) \
			__va(_PAGE_PFN_TO_PADDR(pud_val(pud))) | TBL_SEC_BIT)))
					
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */

#define boot_pud_set_k(pudp, pmdp)	(*(pudp) = mk_pud_phys(pmdp, \
						PAGE_KERNEL_PMD))
#define boot_pud_set_u(pudp, pmdp)	(*(pudp) = mk_pud_phys(pmdp, \
						PAGE_USER_PMD))
#define	boot_pud_page(pud)		\
		(e2k_addr_t)boot_va(_PAGE_PFN_TO_PADDR(pud_val(pud)))

#define mk_pgd_phys_k(pudp)		mk_pgd_addr(pudp, PAGE_KERNEL_PUD)
#ifndef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
#define pgd_set_k(pgdp, pudp)		(*(pgdp) = mk_pgd_phys_k(pudp))
#define	node_pgd_set_k(nid, pgdp, pudp)	pgd_set_k(pgdp, pudp)
#define vmlpt_pgd_set(pgdp, lpt)	pgd_set_u(pgdp, (pud_t *)(lpt))
#else	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
extern void node_pgd_set_k(int nid, pgd_t *pgdp, pud_t *pudp);
static void inline pgd_set_k(pgd_t *pgdp, pud_t *pudp)
{
	node_pgd_set_k(numa_node_id(), pgdp, pudp);
}
#define vmlpt_pgd_set(pgdp, lpt)	pgd_set_u(pgdp, (pud_t *)(lpt))
#endif	/* ! CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
#define pgd_set_u(pgdp, pudp)		(*(pgdp) = mk_pgd_addr(pudp, \
							PAGE_USER_PUD))
#define pgd_none(pgd)			(!pgd_val(pgd))
#define pgd_bad_kernel(pgd)						\
({									\
	unsigned long pgd_value;					\
	int res = 0;							\
	if (!pgd_none(pgd)) {						\
		pgd_value = pgd_val(pgd) &				\
				~(_PFN_MASK | _PAGE_SEC_MAP);		\
		if (pgd_value != _PAGE_KERNEL_PUD)			\
			res = 1;					\
	}								\
	res;								\
})
#define pgd_bad_user(pgd)						\
({									\
	unsigned long pgd_value;					\
	int res = 0;							\
	if (!pgd_none(pgd)) {						\
		pgd_value = pgd_val(pgd) &				\
				~(_PFN_MASK | _PAGE_SEC_MAP);		\
		if (pgd_value != _PAGE_USER_PUD)			\
			res = 1;					\
	}								\
	res;								\
})
#define pgd_bad(pgd)		(pgd_bad_user(pgd) && pgd_bad_kernel(pgd))
#define pgd_present(pgd)	(pgd_val(pgd) & _PAGE_PRESENT)
#define pgd_clear_one(pgdp)	(pgd_val(*(pgdp)) = 0UL)
#define pgd_page(pgd)		((e2k_addr_t) \
				__va(_PAGE_PFN_TO_PADDR(pgd_val(pgd))))

#define boot_mk_pgd_phys_k(pudp)	mk_pgd_phys(pudp, PAGE_KERNEL_PUD)
#define boot_mk_pgd_phys_u(pudp)	mk_pgd_phys(pudp, PAGE_USER_PUD)
#ifndef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
#define boot_pgd_set_k(pgdp, pudp)	(*(pgdp) = boot_mk_pgd_phys_k(pudp))
#define boot_pgd_set_u(pgdp, pudp)	(*(pgdp) = boot_mk_pgd_phys_u(pudp))
#define boot_vmlpt_pgd_set(pgdp, lpt)	(*(pgdp) = boot_mk_pgd_phys_u(	\
							(pud_t *)(lpt)))
#else	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
extern void boot_pgd_set(pgd_t *my_pgdp, pud_t *pudp, int user);
#define boot_pgd_set_k(pgdp, pudp)	boot_pgd_set(pgdp, pudp, 0)
#define boot_pgd_set_u(pgdp, pudp)	boot_pgd_set(pgdp, pudp, 1)
#define boot_vmlpt_pgd_set(pgdp, lpt)	(*(pgdp) = boot_mk_pgd_phys_k(	\
							(pud_t *)(lpt)))
#endif	/* ! CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
#define	boot_pgd_page(pgd)		\
		(e2k_addr_t)boot_va(_PAGE_PFN_TO_PADDR(pgd_val(pgd)))

/*
 * The following have defined behavior only work if pte_present() is true.
 */
#define pte_read(pte)		(1)
#define pte_write(pte)		(pte_val(pte) & _PAGE_W)
#define pte_exec(pte)		((pte_val(pte) & _PAGE_NON_EX) == 0)
#define pte_dirty(pte)		((pte_val(pte) & _PAGE_D) != 0)
#define pte_young(pte)		((pte_val(pte) & _PAGE_A) != 0)
#define pte_huge(pte)		((pte_val(pte) & _PAGE_HUGE) != 0)
#define pte_special(pte)	((pte_val(pte) & _PAGE_SPECIAL) != 0)

#define pte_wrprotect(pte)	(__pte(pte_val(pte) & ~_PAGE_W))
#define pte_mkwrite(pte)	(__pte(pte_val(pte) | _PAGE_W))
#define pte_mkexec(pte)		(__pte(pte_val(pte) & ~_PAGE_NON_EX))
#define pte_mkold(pte)		(__pte(pte_val(pte) & ~_PAGE_A))
#define pte_mkyoung(pte)	(__pte(pte_val(pte) | _PAGE_A))
#define pte_mkclean(pte)	(__pte(pte_val(pte) & ~_PAGE_D))
#define pte_mkdirty(pte)	(__pte(pte_val(pte) | _PAGE_D))

#define pte_mkhuge(pte) 	(__pte(pte_val(pte) | _PAGE_PRESENT | \
							_PAGE_HUGE))
#define	pte_mkspecial(pte)	(__pte(pte_val(pte) | _PAGE_SPECIAL))

/*
 * The pointer of kernel root-level page table directory
 * The Page table directory is allocated and created at boot-time
 */

#ifndef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
extern	pgd_t			swapper_pg_dir[PTRS_PER_PGD];
#else	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
typedef struct pg_dir {
	pgd_t pg_dir[PTRS_PER_PGD];
} pg_dir_t;
extern	pg_dir_t		all_cpus_swapper_pg_dir[NR_CPUS];
#define	swapper_pg_dir		(all_cpus_swapper_pg_dir[0].pg_dir)
#endif	/* ! CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */

#ifndef	CONFIG_NUMA
#ifdef	CONFIG_RECOVERY
#define cntp_kernel_root_pt	swapper_pg_dir
#endif	/* CONFIG_RECOVERY */
#define	kernel_root_pt		swapper_pg_dir
#define	boot_root_pt		boot_vp_to_pp(kernel_root_pt)
#define	node_pg_dir(nid)	((nid), &swapper_pg_dir)
#define	cpu_pg_dir(cpu)		kernel_root_pt
#define the_cpu_pg_dir		cpu_pg_dir
#define	cpu_kernel_root_pt	cpu_pg_dir(dummy)
#else	/* CONFIG_NUMA */
#ifndef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
extern	pgd_t 	__nodedata	*all_nodes_pg_dir[MAX_NUMNODES];
#else	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
extern	pg_dir_t __nodedata	*all_nodes_pg_dir[MAX_NUMNODES];
#endif	/* ! ONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */

#define	node_pg_dir(nid)	(all_nodes_pg_dir[nid])
#ifdef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
#define	my_cpu_pg_dir							\
({									\
	pgd_t *pgdp;							\
									\
	if (THERE_IS_DUP_KERNEL) {					\
		pgdp = all_cpus_swapper_pg_dir[raw_smp_processor_id()].pg_dir; \
	} else {							\
		pgdp = swapper_pg_dir;					\
	}								\
	pgdp;								\
})
#define	the_cpu_pg_dir(cpuid)						\
({									\
	int the_cpu = (cpuid);						\
	int nid = cpu_to_node(the_cpu);					\
	pg_dir_t *node_pgds;						\
	pgd_t *pgdp;							\
									\
	node_pgds = node_pg_dir(nid);					\
	if (THERE_IS_DUP_KERNEL) {					\
		pgdp = node_pgds[the_cpu].pg_dir;			\
	} else {							\
		pgdp = node_pgds[0].pg_dir;				\
	}								\
	pgdp;								\
})
#define	boot_node_cpu_pg_dir(nid, cpuid)				\
({									\
	int cpu_num = (BOOT_THERE_IS_DUP_KERNEL) ? (cpuid) : 0;		\
	boot_the_node_vp_to_pp((nid), 					\
			all_cpus_swapper_pg_dir[cpu_num].pg_dir);	\
})
#define	boot_cpu_pg_dir(cpuid)						\
		boot_node_cpu_pg_dir(boot_numa_node_id(), cpuid)
#define	cpu_kernel_root_pt	my_cpu_pg_dir
#define	boot_cpu_kernel_root_pt	boot_cpu_pg_dir(boot_smp_processor_id())
#define	boot_the_node_root_pt(nid)					\
		boot_node_cpu_pg_dir(nid, 0)		/* for all CPUs */
#define	boot_node_root_pt	boot_cpu_pg_dir(0)	/* for all CPUs */
#define	boot_root_pt		boot_cpu_kernel_root_pt
#ifdef	CONFIG_RECOVERY
#define cntp_kernel_root_pt                                             \
		((pg_dir_t *)cntp_va(all_cpus_swapper_pg_dir, 0))[0].pg_dir
#endif	/* CONFIG_RECOVERY */
#define	kernel_root_pt			cpu_kernel_root_pt
#else	/* ! CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
#define	boot_the_node_root_pt(nid)	boot_node_vp_to_pp(swapper_pg_dir)
#define	boot_node_root_pt		boot_the_node_root_pt(dummy)
#define	boot_root_pt			boot_node_root_pt
#ifdef	CONFIG_RECOVERY
#define cntp_kernel_root_pt                                             \
		((pgd_t **)cntp_va(all_nodes_pg_dir, 0))[0]
#endif	/* CONFIG_RECOVERY */
#define	kernel_root_pt			node_pg_dir(numa_node_id())
#define	cpu_pg_dir(cpu)			kernel_root_pt
#define	cpu_kernel_root_pt		cpu_pg_dir(dummy)
#endif	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
#endif	/* ! CONFIG_NUMA */

#ifdef	CONFIG_SECONDARY_SPACE_SUPPORT
extern	e2k_addr_t	sec_zeroed_page;
extern	i386_pgd_t	*empty_sec_pg_dir;
#endif	/* CONFIG_SECONDARY_SPACE_SUPPORT */

extern	void paging_init(void);

/*
 * The index and offset in the root-level page table directory.
 */
#define	pgd_index(virt_addr)		(((virt_addr) >> PGDIR_SHIFT) & \
					(PTRS_PER_PGD - 1))
#define pgd_offset(mm, virt_addr)	((mm)->pgd + pgd_index(virt_addr))
#ifdef	CONFIG_RECOVERY
#define cntp_pgd_offset(mm, virt_addr)					\
		((pgd_t *)cntp_va((mm)->pgd, 0) + pgd_index(virt_addr))
#endif	/* CONFIG_RECOVERY */
#define	pgd_to_index(pgdp)		((((unsigned long)(pgdp)) / 	\
						(sizeof (pgd_t))) &	\
							(PTRS_PER_PGD - 1))
#define	pgd_to_page(pgdp)		((pgdp) - pgd_to_index(pgdp))
/* to find an entry in a kernel root page-table-directory */
#define pgd_offset_k(virt_addr)		((pgd_t *)kernel_root_pt + 	\
						pgd_index(virt_addr))
#ifdef	CONFIG_RECOVERY
#define cntp_pgd_offset_k(virt_addr)					\
		((pgd_t *)cntp_va(cntp_kernel_root_pt, 0) +		\
		pgd_index(virt_addr))
#endif	/* CONFIG_RECOVERY */
#define pgd_offset_kernel(virt_addr)	pgd_offset_k(virt_addr)
#ifdef	CONFIG_RECOVERY
#define cntp_pgd_offset_kernel(virt_addr)	cntp_pgd_offset_k(virt_addr)
#endif	/* CONFIG_RECOVERY */
#define	boot_pgd_index(virt_addr)	pgd_index(virt_addr)
#define boot_pgd_offset_k(virt_addr)	((pgd_t *)boot_root_pt +	\
						boot_pgd_index(virt_addr))
#ifdef	CONFIG_NUMA
#ifdef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
extern pgd_t *node_pgd_offset_kernel(int nid, e2k_addr_t virt_addr);
#else	/* ! CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
#define node_pgd_offset_kernel(nid, virt_addr)				\
		(node_pg_dir(nid) + pgd_index(virt_addr))
#endif	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
#else	/* ! CONFIG_NUMA */
#define node_pgd_offset_kernel(nid, virt_addr)	pgd_offset_kernel(virt_addr)
#endif	/* CONFIG_NUMA */

#ifndef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
#define pgd_clear(pgdp)		pgd_clear_one(pgdp)
#else	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
static inline int
pgd_clear_cpu_root_pt(pgd_t *pgd)
{
	pgd_t *pgd_table = pgd_to_page(pgd);
	unsigned long pgd_ind;
	pgd_t *cpu_pgd;

	if (!THERE_IS_DUP_KERNEL)
		return 0;
	if (!current->active_mm || current->active_mm->pgd != pgd_table)
		return 0;
	pgd_ind = pgd_to_index(pgd);
	cpu_pgd = &cpu_kernel_root_pt[pgd_ind];
	if (pgd_none(*cpu_pgd)) {
		printk("pgd_clear_cpu_root_pt() CPU #%u kernel root "
			"pgd %p already clean 0x%lx\n",
			smp_processor_id(),
			cpu_pgd, pgd_val(*cpu_pgd));
		print_stack(current);
	}
	pgd_clear_one(cpu_pgd);
	return 1;
}
static inline void
pgd_clear(pgd_t *pgd)
{
	unsigned long mask;

	/*
	 * PGD clearing should be done into two root page tables (main and
	 * CPU's) and in atomic style, so close interrupts to preserve
	`* from smp call for flush_tlb_all() between two clearing
	 * while the CPU restore CPU's root PGD from main. In this case
	 * CPU's PGD will be restored as clean when we wait for not
	 * yet cleared state (see above pgd_clear_cpu_root_pt())
	 */
	raw_local_irq_save(mask);
	pgd_clear_one(pgd);		/* order of clearing is significant */
	pgd_clear_cpu_root_pt(pgd);	/* if interrupts do not close */
					/* and flush of TLB can restore */
					/* second PGD from first PGD */
	raw_local_irq_restore(mask);
}
#endif	/* ! CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */

/*
 * The index and offset in the upper page table directory.
 */
#define	pud_index(virt_addr)		((virt_addr >> PUD_SHIFT) & \
					(PTRS_PER_PUD - 1))
#define	pud_virt_offset(virt_addr)	(KERNEL_VMLPT_BASE_ADDR | \
					((pmd_virt_offset(virt_addr) & \
					PTE_MASK) >> \
					(E2K_VA_SIZE - PGDIR_SHIFT)))
#define pud_offset_kernel(dir, address)	((pud_t *)pgd_page(*(dir)) + \
						pud_index(address))
#define pud_offset(dir, address)	pud_offset_kernel(dir, address)
#define pud_offset_k(virt_addr)		(pud_t *)pud_virt_offset(virt_addr)

#define	boot_pud_index(virt_addr)	pud_index(virt_addr)
#define boot_pud_offset(pgdp, addr)	((pud_t *)boot_pgd_page(*(pgdp)) + \
					boot_pud_index(addr))

/*
 * The index and offset in the middle page table directory
 */
#define	pmd_index(virt_addr)		((virt_addr >> PMD_SHIFT) & \
					(PTRS_PER_PMD - 1))
#define	pmd_virt_offset(virt_addr)	(KERNEL_VMLPT_BASE_ADDR | \
					((pte_virt_offset(virt_addr) & \
					PTE_MASK) >> \
					(E2K_VA_SIZE - PGDIR_SHIFT)))
#define pmd_offset_kernel(pud, address)	((pmd_t *) pud_page(*(pud)) + \
						pmd_index(address))
#define pmd_offset(pud, address)	pmd_offset_kernel(pud, address)
#define pmd_offset_k(virt_addr)		(pmd_t *)pmd_virt_offset(virt_addr)

#define	boot_pmd_index(virt_addr)	pmd_index(virt_addr)
#define boot_pmd_offset(pudp, addr)	((pmd_t *)boot_pud_page(*(pudp)) + \
					boot_pmd_index(addr))

/*
 * #define boot_pmd_index(virt_addr)	pmd_index(virt_addr)
 * #define boot_pmd_offset(pgdp, addr)	((pmd_t *)boot_pgd_page(*(pgdp)) + \
 *					boot_pmd_index(addr))
 */

/*
 * The index and offset in the third-level page table.
 */
#define	pte_index(virt_addr)		((virt_addr >> PAGE_SHIFT) & \
					(PTRS_PER_PTE - 1))
#define	pte_virt_offset(virt_addr)	(KERNEL_VMLPT_BASE_ADDR | \
					(((virt_addr) & PTE_MASK) >> \
					(E2K_VA_SIZE - PGDIR_SHIFT)))
#define pte_offset_kernel(pmd, address)	\
		((pte_t *)pmd_page_kernel(*(pmd)) + \
					pte_index(address))
#define pte_offset_map(pmd, address)	pte_offset_kernel(pmd, address)
#define pte_unmap(pte)				do { } while (0)

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT

#define _PAGE_SECONDARY_PT	(_PAGE_USER_PT | _PAGE_SEC_MAP)
#define PAGE_SECONDARY_PT	__pgprot(_PAGE_SECONDARY_PT)
#define FREEZE_MASK		(_PAGE_P | _PAGE_VALID)
#define _PAGE_KERNEL_FROZEN 	(_PAGE_SECONDARY_PT & ~FREEZE_MASK)
#define pud_frozen(pud)		((pud_val(pud) & ~_PFN_MASK) == \
                                                (_PAGE_KERNEL_FROZEN))
#define mk_pud_frozen(pudp)						\
({									\
		DebugSS("PUD:0x%lx\n", pud_val(*pudp));	\
		*(pudp)=__pud(pud_val(*pudp) & ~FREEZE_MASK);		\
})

#define unfreeze_pud(pudp)						\
({									\
		DebugSS("PUD:0x%lx\n", pud_val(*pudp));	\
		(*(pudp)=__pud(pud_val(*pudp) | FREEZE_MASK));		\
})

#define pmd_frozen(pmd)		((pmd_val(pmd) & ~_PFN_MASK) == \
                                                (_PAGE_KERNEL_FROZEN))
#define mk_pmd_frozen(pmdp)						\
({									\
		DebugSS("PMD:0x%lx\n", pmd_val(*pmdp));	\
		(*(pmdp)=__pmd(pmd_val(*pmdp) & ~FREEZE_MASK));		\
})

#define unfreeze_pmd(pmdp)						\
({									\
		DebugSS("PMD:0x%lx\n", pmd_val(*pmdp));	\
		(*(pmdp)=__pmd(pmd_val(*pmdp) | FREEZE_MASK));		\
})
/*
 * Some trick: when address points on secondary p?d-table, we mark
 * 62(unused) bit of the address...
 */
#define	TBL_SEC_SHIFT		62
#define	TBL_SEC_BIT		(1UL <<	TBL_SEC_SHIFT)	/* Secondary tbl addr */
#define	is_sec_table(a)		((u64)a & TBL_SEC_BIT)
#define	mark_sec(v, a)		((((v & _PAGE_SEC_MAP) ? 1UL : 0UL) \
					<< TBL_SEC_SHIFT) | (u64)a)

#else /* !CONFIG_SECONDARY_SPACE_SUPPORT: */

#define TBL_SEC_BIT		0

#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */

/*
 * On E3S a large page occupies two sequential
 * entries in page table on 2nd level (PMD)
 */
#define pte_offset_k(virt_addr, large_page) \
		(large_page) ? \
			(pte_t *)pmd_virt_offset((virt_addr) & \
							E2K_LARGE_PAGE_MASK) \
			: (pte_t *)pte_virt_offset(virt_addr)
#define boot_pte_offset_k(virt_addr, large_page) \
		(large_page) ? \
			(pte_t *)pmd_virt_offset((virt_addr) & \
					BOOT_E2K_LARGE_PAGE_MASK) \
			: (pte_t *)pte_virt_offset(virt_addr)

#define get_pte_offset_k(virt_addr) \
	( { \
		pte_t *pte; \
		pmd_t *pmd = (pmd_t *) pmd_virt_offset((virt_addr) & \
				E2K_LARGE_PAGE_MASK); \
		if (!pmd_large(*pmd)) \
			pte = (pte_t *) pte_virt_offset(virt_addr); \
		else \
			pte = (pte_t *) pmd; \
		pte; \
	} )

#define	boot_pte_index(virt_addr)	pte_index(virt_addr)
#define boot_pte_offset(pmdp, addr)	((pte_t *)boot_pmd_page(*(pmdp)) + \
						boot_pte_index(addr))

extern void pgd_clear_bad(pgd_t *);
extern void pud_clear_bad(pud_t *);
extern void pmd_clear_bad(pmd_t *);

static inline int pmd_none_or_clear_bad_kernel(pmd_t *pmd)
{
	if (pmd_none(*pmd))
		return 1;
	if (unlikely(pmd_bad_kernel(*pmd))) {
		pmd_clear_bad(pmd);
		return 1;
	}
	return 0;
}
static inline int pud_none_or_clear_bad_kernel(pud_t *pud)
{
	if (pud_none(*pud))
		return 1;
	if (unlikely(pud_bad_kernel(*pud))) {
		pud_clear_bad(pud);
		return 1;
	}
	return 0;
}
static inline int pgd_none_or_clear_bad_kernel(pgd_t *pgd)
{
	if (pgd_none(*pgd))
		return 1;
	if (unlikely(pgd_bad_kernel(*pgd))) {
		pgd_clear_bad(pgd);
		return 1;
	}
	return 0;
}

/*
 * Encode and de-code a swap entry
 *
 * Format of swap pte:
 *	bit   0   : present bit (must be zero)
 *	bit  12   : _PAGE_FILE (must be zero)
 *	bits 13-19: swap-type
 *		    if ! (CONFIG_MAKE_ALL_PAGES_VALID):
 *	bits 20-63: swap offset
 *		    else if (CONFIG_MAKE_ALL_PAGES_VALID)
 *	bits 20-39: low part of swap offset
 *	bit  40   : _PAGE_VALID (must be one)
 *	bits 41-63: hi part of swap offset
 *
 * Format of file pte:
 *	bit   0   : present bit (must be zero)
 *	bit  12   : _PAGE_FILE (must be one)
 *		    if ! (CONFIG_MAKE_ALL_PAGES_VALID):
 *	bits 13-63: file_offset/PAGE_SIZE
 *		    else if (CONFIG_MAKE_ALL_PAGES_VALID)
 *	bits 13-39: low part of file_offset/PAGE_SIZE
 *	bit  40   : _PAGE_VALID (must be one)
 *	bits 41-63: hi part of file_offset/PAGE_SIZE
 */
#define __SWP_TYPE_BITS		7
#define MAX_SWAPFILES_CHECK()	BUILD_BUG_ON(MAX_SWAPFILES_SHIFT > \
					     __SWP_TYPE_BITS)
#define __SWP_TYPE_SHIFT		(PAGE_SHIFT + 1)
#define __SWP_OFFSET_SHIFT	(__SWP_TYPE_SHIFT + __SWP_TYPE_BITS)
#define __FILE_PGOFF_SHIFT	(PAGE_SHIFT + 1)

#define pte_file(pte)		(pte_val(pte) & _PAGE_FILE)
#define	_PAGE_FILE		(1UL << PAGE_SHIFT)
#define __swp_type(entry)	(((entry).val >> __SWP_TYPE_SHIFT) & \
				 ((1U << __SWP_TYPE_BITS) - 1))
#define __pte_to_swp_entry(pte)	((swp_entry_t) { pte_val(pte) })

#ifndef	CONFIG_MAKE_ALL_PAGES_VALID
#define __swp_offset(entry)	((entry).val >> __SWP_OFFSET_SHIFT)
#define __swp_entry(type, offset)	((swp_entry_t) { \
					 ((type) << __SWP_TYPE_SHIFT) | \
					 ((offset) << __SWP_OFFSET_SHIFT) })
#define __swp_entry_to_pte(x)	((pte_t) { (x).val })
#define	pte_to_pgoff(pte)	(pte_val(pte) >> __FILE_PGOFF_SHIFT)
#define pgoff_to_pte(off)	(__pte(((off) << __FILE_PGOFF_SHIFT) | \
				       _PAGE_FILE))
#define PTE_FILE_MAX_BITS	(64 - __FILE_PGOFF_SHIFT)
#else
#define	INSERT_VALID(off)	(((off) & (_PAGE_VALID - 1UL)) | \
				(((off) & ~(_PAGE_VALID - 1UL)) << 1))
#define	REMOVE_VALID(off)	(((off) & (_PAGE_VALID - 1UL)) | \
				(((off >> 1) & ~(_PAGE_VALID - 1UL))))
#define __swp_offset(entry) (REMOVE_VALID((entry).val) >> __SWP_OFFSET_SHIFT)
#define __swp_entry(type, off)	((swp_entry_t) { \
				 (((type) << __SWP_TYPE_SHIFT) | \
				 INSERT_VALID(((off) << __SWP_OFFSET_SHIFT))) })

#define __swp_entry_to_pte(entry) ((pte_t) { (entry).val | _PAGE_VALID })

#define	pte_to_pgoff(pte) (REMOVE_VALID(pte_val(pte)) >> __FILE_PGOFF_SHIFT)
#define pgoff_to_pte(off) (__pte((INSERT_VALID((off) << __FILE_PGOFF_SHIFT)) \
					| _PAGE_FILE | _PAGE_VALID))
#define PTE_FILE_MAX_BITS (64 - __FILE_PGOFF_SHIFT - 1)
#endif	/* CONFIG_MAKE_ALL_PAGES_VALID */

/*
 * atomic versions of the some PTE manipulations:
 */

#ifdef CONFIG_SMP
static inline int 
ptep_test_and_clear_atomic(int nr, unsigned long addr, pte_t *ptep)
{
	int rval;

	rval = test_and_clear_bit(nr, ptep);

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (TASK_IS_BINCO(current) && ADDR_IN_SS(addr) && !IS_UPT_E3S) {
		u64		t = (u64)ptep & PTE_MASK;
		i386_pte_t	*iptep;

		t = IS_FIRST_PTE(addr)? (t + PAGE_SIZE * 2) : (t + PAGE_SIZE);
		iptep = (i386_pte_t *)t + i386_pte_index(addr);
		test_and_clear_bit_32(nr, iptep);
	}
#endif

	return rval;
}
#endif /* CONFIG_SMP */

static inline int
ptep_test_and_clear_young(struct vm_area_struct *vma, unsigned long addr, pte_t *ptep)
{
#ifdef CONFIG_SMP
	return ptep_test_and_clear_atomic(_PAGE_A_BIT, addr, ptep);
#else
	pte_t pte = *ptep;
	if (!pte_young(pte))
		return 0;
	set_pte_at(vma->vm_mm, addr, ptep, pte_mkold(pte));
	return 1;
#endif
}

static inline int
ptep_test_and_clear_dirty(struct vm_area_struct *vma, unsigned long addr, pte_t *ptep)
{
#ifdef CONFIG_SMP
	return ptep_test_and_clear_atomic(_PAGE_D_BIT, addr, ptep);
#else
	pte_t pte = *ptep;
	if (!pte_dirty(pte))
		return 0;
	set_pte_at(vma->vm_mm, addr, ptep, pte_mkclean(pte));
	return 1;
#endif
}

static inline pte_t
do_ptep_get_and_clear(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
#ifdef CONFIG_SMP
	return __pte(xchg(&ptep->pte, 0));
#else
	pte_t pte = *ptep;
	pte_clear(mm, addr, ptep);
	return pte;
#endif
}

static inline pte_t
do_ptep_get_and_clear_as_valid(pte_t *ptep)
{
#ifdef CONFIG_SMP
	return __pte(__api_atomic64_get_old_clear_mask(~_PAGE_VALID, ptep));
#else
	pte_t pte = *ptep;
	pte_val(*ptep) &= ~_PAGE_VALID;
	return pte;
#endif
}

static inline pte_t
ptep_get_and_clear(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
	if (TASK_IS_BINCO(current) && ADDR_IN_SS(addr) && !IS_UPT_E3S) {
		pte_t pte = *ptep;
		pte_clear(mm, addr, ptep);
		return pte;
	}

	return do_ptep_get_and_clear(mm, addr, ptep);
}

static inline pte_t
ptep_get_and_clear_as_valid(struct mm_struct *mm, unsigned long addr,
				pte_t *ptep)
{
	if (TASK_IS_BINCO(current) && ADDR_IN_SS(addr) && !IS_UPT_E3S) {
		pte_t pte = *ptep;
		pte_clear(mm, addr, ptep);
		return pte;
	}

	return do_ptep_get_and_clear_as_valid(ptep);
}

#ifdef CONFIG_SMP
static inline void ptep_wrprotect_atomic(unsigned long addr, pte_t *ptep)
{
	clear_bit(_PAGE_W_BIT, ptep);

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (TASK_IS_BINCO(current) && ADDR_IN_SS(addr) && !IS_UPT_E3S) {
		u64		t = (u64)ptep & PTE_MASK;
		i386_pte_t	*iptep;

		t = IS_FIRST_PTE(addr)? (t + PAGE_SIZE * 2) : (t + PAGE_SIZE);
		iptep = (i386_pte_t *)t + i386_pte_index(addr);
		clear_bit_32(_PAGE_W_BIT, iptep);
	}
#endif
}
#endif /* CONFIG_SMP */

static inline void
ptep_set_wrprotect(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
#ifdef CONFIG_SMP
	ptep_wrprotect_atomic(addr, ptep);
#else
	pte_t pte = *ptep;
	pte = pte_wrprotect(pte);
	set_pte_at(mm, addr, ptep, pte);
#endif
}

#ifdef CONFIG_MAKE_ALL_PAGES_VALID
# define ptep_clear_flush_as_valid(__vma, __address, __ptep)		\
({									\
	pte_t __pte;							\
	__pte = ptep_get_and_clear_as_valid((__vma)->vm_mm, __address, __ptep);\
	flush_tlb_page(__vma, __address);				\
	__pte;								\
})
#endif /* CONFIG_MAKE_ALL_PAGES_VALID */

#endif	/* !(__ASSEMBLY__) */

/*
 * No page table caches to initialise
 */
#define pgtable_cache_init()	do { } while (0)

#define __HAVE_ARCH_PMD_WRITE
#define __HAVE_ARCH_PTEP_MODIFY_PROT_TRANSACTION
#define __HAVE_ARCH_PTEP_TEST_AND_CLEAR_YOUNG
#define __HAVE_ARCH_PTEP_TEST_AND_CLEAR_DIRTY
#define __HAVE_ARCH_PTEP_GET_AND_CLEAR
#define __HAVE_ARCH_PTEP_SET_WRPROTECT
#define __HAVE_ARCH_PMDP_TEST_AND_CLEAR_YOUNG
#define __HAVE_ARCH_PMDP_SPLITTING_FLUSH
#define __HAVE_ARCH_PMDP_GET_AND_CLEAR
#define __HAVE_ARCH_PMDP_SET_WRPROTECT
#include <asm-generic/pgtable.h>

static inline pte_t ptep_modify_prot_start(struct mm_struct *mm,
					   unsigned long addr,
					   pte_t *ptep)
{
	if (TASK_IS_BINCO(current) && ADDR_IN_SS(addr) && !IS_UPT_E3S) {
		pte_t pte = *ptep;
		pte_clear(mm, addr, ptep);
		return pte;
	}

	return __pte(__api_atomic64_get_old_clear_mask(~_PAGE_VALID, ptep));
}

static inline void ptep_modify_prot_commit(struct mm_struct *mm,
					   unsigned long addr,
					   pte_t *ptep, pte_t pte)
{
	__ptep_modify_prot_commit(mm, addr, ptep, pte);
}


static inline int pmdp_test_and_clear_young(struct vm_area_struct *vma,
					    unsigned long addr, pmd_t *pmdp)
{
#ifdef CONFIG_SMP
	return test_and_clear_bit(_PAGE_A_BIT, pmdp);
#else
	pmd_t pmd = *pmdp;
	if (!pmd_young(pmd))
		return 0;
	set_pmd_at(vma->vm_mm, addr, pmdp, pmd_mkold(pmd));
	return 1;
#endif
}

extern void pmdp_splitting_flush(struct vm_area_struct *vma,
			  unsigned long address, pmd_t *pmdp);

static inline pmd_t pmdp_get_and_clear(struct mm_struct *mm, unsigned long addr,
				       pmd_t *pmdp)
{
#ifdef CONFIG_SMP
	return __pmd(xchg(&pmdp->pmd, 0));
#else
	pmd_t pmd = *pmdp;
	pmd_clear(pmdp);
	return pmd;
#endif
}

static inline void pmdp_set_wrprotect(struct mm_struct *mm,
				      unsigned long addr, pmd_t *pmdp)
{
	clear_bit(_PAGE_W_BIT, pmdp);
}

/*
 * One need it to avoid BUILD_BUG() in generic pmdp_clear_flush_young().
 */
#if !defined(CONFIG_TRANSPARENT_HUGEPAGE)
#define __HAVE_ARCH_PMDP_CLEAR_YOUNG_FLUSH
static inline  int pmdp_clear_flush_young(struct vm_area_struct *vma,
			unsigned long address, pmd_t *pmdp)
{
	BUG();
	return 0;
}
#endif

#endif /* !(_E2K_PGTABLE_H) */
