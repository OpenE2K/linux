/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * E2K page table operations.
 */

#ifndef _E2K_PGTABLE_H
#define _E2K_PGTABLE_H

#define PCI_IO_START            0x00000000
#define PCI_IO_DOMAIN_SIZE      0x00004000
#define PCI_IO_END              0x00010000
#define PCI_MEM_START           0x80000000UL
#define PCI_MEM_DOMAIN_SIZE     0x10000000UL
#define PCI_MEM_END             0xF7FFFFFFUL

/*
 * This file contains the functions and defines necessary to modify and
 * use the E2K page tables.
 * NOTE: E2K has four levels of page tables, while Linux assumes that
 * there are three levels of page tables.
 */

#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <asm/numa.h>
#include <linux/topology.h>

#include <asm/pgtable_def.h>
#include <asm/system.h>
#include <asm/cpu_regs.h>
#include <asm/head.h>
#include <asm/bitops.h>
#include <asm/machdep.h>
#include <asm/secondary_space.h>
#include <asm/mmu_regs_access.h>
#include <asm/tlb_regs_access.h>
#include <asm/pgatomic.h>


#define pgtable_l4_enabled	1
#define pgtable_l5_enabled	0


extern u32 save_tags_colors_from_data(u64 *datap, u8 *tagp, u8 *clrp);
extern void restore_tags_colors_for_data(u64 *datap, u8 *tagp, u8 *clrp);

extern int e2k_swap_save_tags(struct page *page);
extern void e2k_swap_restore_tags(swp_entry_t entry, struct page *page);
extern void e2k_swap_invalidate_tags(int type, pgoff_t offset);
extern void e2k_swap_invalidate_tags_area(int type);


#define pgdp_to_p4dp(pgdp)	((p4d_t *) (pgdp))
#define p4dp_to_pgdp(p4dp)	((pgd_t *) (p4dp))

#define __HAVE_ARCH_PREPARE_TO_SWAP
static inline int arch_prepare_to_swap(struct page *page)
{
	return e2k_swap_save_tags(page);
}

#define __HAVE_ARCH_SWAP_INVALIDATE
static inline void arch_swap_invalidate_page(int type, pgoff_t offset)
{
	e2k_swap_invalidate_tags(type, offset);
}

static inline void arch_swap_invalidate_area(int type)
{
	e2k_swap_invalidate_tags_area(type);
}

#define __HAVE_ARCH_SWAP_RESTORE
static inline void arch_swap_restore(swp_entry_t entry, struct folio *folio)
{
	e2k_swap_restore_tags(entry, &folio->page);
}

/*
 * e2k doesn't have any external MMU info: the kernel page
 * tables contain all the necessary information.
 */
static inline void update_mmu_cache(struct vm_area_struct *vma,
				    unsigned long address, pte_t *pte)
{
}

static inline void update_mmu_cache_pmd(struct vm_area_struct *vma,
					unsigned long address, pmd_t *pmd)
{
}

static inline void update_mmu_cache_pud(struct vm_area_struct *vma,
					unsigned long address, pud_t *pud)
{
}

/*
 * The defines and routines to manage and access the four-level
 * page table.
 */

#define validate_pte_at(mm, addr, ptep, pteval) \
do { \
	trace_pt_update("validate_pte_at: mm 0x%lx, addr 0x%lx, ptep 0x%lx, value 0x%lx\n", \
			(mm), (addr), (ptep), pte_val(pteval)); \
	native_set_pte_noflush(ptep, pteval); \
} while (0)
#define	boot_set_pte_at(addr, ptep, pteval)	\
		native_set_pte(ptep, pteval, false)
#define	boot_set_pte_kernel(addr, ptep, pteval)	\
		boot_set_pte_at(addr, ptep, pteval)

#define validate_pmd_at(mm, addr, pmdp, pmdval)	\
do { \
	trace_pt_update("validate_pmd_at: mm 0x%lx, addr 0x%lx, pmdp 0x%lx, value 0x%lx\n", \
			(mm), (addr), (pmdp), pmd_val(pmdval)); \
	native_set_pmd_noflush(pmdp, pmdval); \
} while (0)

#define validate_pud_at(mm, addr, pudp, pudval)	\
		set_pud_at(mm, addr, pudp, pudval)

#define validate_p4d_at(mm, addr, p4dp)	\
		set_p4d_at(mm, addr, p4dp, __p4d(_PAGE_INIT_VALID))

#define	get_pte_for_address(vma, address) \
		native_do_get_pte_for_address(vma, address)

#define pud_clear_kernel(pudp)		(pud_val(*(pudp)) = 0UL)
#define pmd_clear_kernel(pmdp)		(pmd_val(*(pmdp)) = 0UL)
#define pte_clear_kernel(ptep)		(pte_val(*(ptep)) = 0UL)

/* pte_page() returns the 'struct page *' corresponding to the PTE: */
#define pte_page(pte) pfn_to_page(pte_pfn(pte))
#define pmd_page(pmd) pfn_to_page(pmd_pfn(pmd))
#define pud_page(pud) pfn_to_page(pud_pfn(pud))
#define p4d_page(p4d) pfn_to_page(p4d_pfn(p4d))

static inline pud_t *p4d_pgtable(p4d_t p4d)
{
	return (pud_t *)__va(p4d_val(p4d) & PTE_PFN_MASK);
}

#define pmd_set_k(pmdp, ptep)	(*(pmdp) = mk_pmd_addr(ptep, \
							PAGE_KERNEL_PTE))
#define pmd_set_u(pmdp, ptep)	(*(pmdp) = mk_pmd_addr(ptep, \
							PAGE_USER_PTE))

static inline unsigned long pte_page_vaddr(pte_t pte)
{
	return (unsigned long) __va(_PAGE_PFN_TO_PADDR(pte_val(pte)));
}

static inline unsigned long pmd_page_vaddr(pmd_t pmd)
{
	return (unsigned long) __va(_PAGE_PFN_TO_PADDR(pmd_val(pmd)));
}

static inline unsigned long pud_page_vaddr(pud_t pud)
{
	return (unsigned long) __va(_PAGE_PFN_TO_PADDR(pud_val(pud)));
}

static inline unsigned long p4d_page_vaddr(p4d_t p4d)
{
	return (unsigned long) __va(_PAGE_PFN_TO_PADDR(p4d_val(p4d)));
}

static inline pmd_t *pud_pgtable(pud_t pud)
{
	return (pmd_t *)__va(_PAGE_PFN_TO_PADDR(pud_val(pud)));
}

#define pud_set_k(pudp, pmdp)		(*(pudp) = mk_pud_addr(pmdp, PAGE_KERNEL_PMD))
#define pud_set_u(pudp, pmdp)		(*(pudp) = mk_pud_addr(pmdp, PAGE_USER_PMD))

#define mk_p4d_phys_k(pudp)		mk_p4d_addr(pudp, PAGE_KERNEL_PUD)

#define p4d_set_k(p4dp, pudp)		(*(p4dp) = mk_p4d_phys_k(pudp))
#define p4d_set_u(p4dp, pudp)		(*(p4dp) = mk_p4d_addr(pudp, PAGE_USER_PUD))

#define vmlpt_pgd_set(pgdp, lpt) \
		(*(pgdp) = __pgd(_PAGE_PADDR_TO_PFN(__pa(lpt)) | _PAGE_KERNEL_PT))

static inline void native_set_pte_noflush(pte_t *ptep, pte_t pteval)
{
	prefetch_offset(ptep, PREFETCH_STRIDE);
	*ptep = pteval;
}

static inline void native_set_pmd_noflush(pmd_t *pmdp, pmd_t pmdval)
{
	*pmdp = pmdval;
}

#if !defined(CONFIG_BOOT_E2K) && !defined(E2K_P2V)
#include <asm/cacheflush.h>

/*
 * When instruction page changes its physical address, we must
 * flush old physical address from Instruction Cache, otherwise
 * it could be accessed by its virtual address.
 *
 * Since we do not know whether the instruction page will change
 * its address in the future, we have to be conservative here.
 */
static inline void flush_pte_from_ic(pte_t val)
{
	unsigned long address;

	address = (unsigned long) __va(_PAGE_PFN_TO_PADDR(pte_val(val)));
	flush_icache_range(address, address + PTE_SIZE);
}

static inline void flush_pmd_from_ic(pmd_t val)
{
	unsigned long address;

	address = (unsigned long) __va(_PAGE_PFN_TO_PADDR(pmd_val(val)));
	flush_icache_range(address, address + PMD_SIZE);
}

static inline void flush_pud_from_ic(pud_t val)
{
	/* pud is too large to step through it, so flush everything at once */
	__flush_icache_all();
}

static __always_inline void native_set_pte(pte_t *ptep, pte_t pteval,
					   bool known_not_present)
{
	prefetch_offset(ptep, PREFETCH_STRIDE);

	BUILD_BUG_ON(!__builtin_constant_p(known_not_present));
	/* If we know that pte is not present, then this means
	 * that instruction buffer has been flushed already
	 * and we can avoid the check altogether. */

	if (known_not_present) {
		*ptep = pteval;
	} else {
		pte_t oldpte = *ptep;

		*ptep = pteval;

		if (pte_present_and_exec(oldpte) &&
		    (!pte_present_and_exec(pteval) ||
		     pte_pfn(oldpte) != pte_pfn(pteval)))
			flush_pte_from_ic(oldpte);
	}
}

static inline void native_set_pmd(pmd_t *pmdp, pmd_t pmdval)
{
	pmd_t oldpmd = *pmdp;

	*pmdp = pmdval;

	if (pmd_present_and_exec_and_huge(oldpmd) &&
	    (!pmd_present_and_exec_and_huge(pmdval) ||
	     pmd_pfn(oldpmd) != pmd_pfn(pmdval)))
		flush_pmd_from_ic(oldpmd);
}

static inline void native_set_pud(pud_t *pudp, pud_t pudval)
{
	pud_t oldpud = *pudp;

	*pudp = pudval;

	if (pud_present_and_exec_and_huge(oldpud) &&
	    (!pud_present_and_exec_and_huge(pudval) ||
	     pud_pfn(oldpud) != pud_pfn(pudval)))
		flush_pud_from_ic(oldpud);
}

static inline void native_set_p4d(p4d_t *p4dp, p4d_t p4dval)
{
	*p4dp = p4dval;
}

static inline void native_set_pgd(pgd_t *pgdp, pgd_t pgdval)
{
	*pgdp = pgdval;
}
#else
# define native_set_pte(ptep, pteval, known_not_present) (*(ptep) = (pteval))
# define native_set_pmd(pmdp, pmdval)	(*(pmdp) = (pmdval))
# define native_set_pud(pudp, pudval)	(*(pudp) = (pudval))
# define native_set_p4d(p4dp, p4dval)	(*(p4dp) = (p4dval))
# define native_set_pgd(pgdp, pgdval)	(*(pgdp) = (pgdval))
#endif

static inline void set_pte(pte_t *ptep, pte_t pteval)
{
	if (TRACE_PT_UPDATES > 1)
		trace_pt_update("set_pte: ptep 0x%lx, value 0x%lx\n",
				ptep, pte_val(pteval));
	native_set_pte(ptep, pteval, false);
}

static inline void set_pte_at(struct mm_struct *mm, unsigned long addr,
			      pte_t *ptep, pte_t pteval)
{
	trace_pt_update("set_pte_at: mm 0x%lx, addr 0x%lx, ptep 0x%lx, value 0x%lx\n",
			mm, addr, ptep, pte_val(pteval));
	native_set_pte(ptep, pteval, false);
}

static inline void set_pte_not_present_at(struct mm_struct *mm, unsigned long addr,
					  pte_t *ptep, pte_t pteval)
{
	trace_pt_update("set_pte_not_present_at: mm 0x%lx, addr 0x%lx, ptep 0x%lx, value 0x%lx\n",
			mm, addr, ptep, pte_val(pteval));
	native_set_pte(ptep, pteval, true);
}

static inline void set_pmd(pmd_t *pmdp, pmd_t pmdval)
{
	if (TRACE_PT_UPDATES > 1)
		trace_pt_update("set_pmd: pmdp 0x%lx, value 0x%lx\n", pmdp, pmd_val(pmdval));
	native_set_pmd(pmdp, pmdval);
}

static inline void set_pmd_at(struct mm_struct *mm, unsigned long addr,
			      pmd_t *pmdp, pmd_t pmdval)
{
	trace_pt_update("set_pmd_at: mm 0x%lx, addr 0x%lx, pmdp 0x%lx, value 0x%lx\n",
			mm, addr, pmdp, pmd_val(pmdval));
	native_set_pmd(pmdp, pmdval);
}

static inline void pmd_clear(pmd_t *pmdp)
{
	trace_pt_update("pmd_clear: pmdp 0x%lx, value 0x%lx\n",
			pmdp, _PAGE_INIT_VALID);
	VM_BUG_ON(pmd_val(*pmdp) & KERNEL_PT_MARK);
	native_set_pmd(pmdp, __pmd(_PAGE_INIT_VALID));
}

static inline void set_pud(pud_t *pudp, pud_t pudval)
{
	if (TRACE_PT_UPDATES > 1)
		trace_pt_update("set_pud: pudp 0x%lx, value 0x%lx\n",
				pudp, pud_val(pudval));
	native_set_pud(pudp, pudval);
}

static inline void set_pud_at(struct mm_struct *mm, unsigned long addr,
			      pud_t *pudp, pud_t pudval)
{
	trace_pt_update("set_pud_at: mm 0x%lx, addr 0x%lx, pudp 0x%lx, value 0x%lx\n",
			mm, addr, pudp, pud_val(pudval));
	native_set_pud(pudp, pudval);
}

static inline void pud_clear(pud_t *pudp)
{
	trace_pt_update("pud_clear: pudp 0x%lx, value 0x%lx\n",
			pudp, _PAGE_INIT_VALID);
	VM_BUG_ON(pud_val(*pudp) & KERNEL_PT_MARK);
	native_set_pud(pudp, __pud(_PAGE_INIT_VALID));
}

static inline void set_p4d(p4d_t *p4dp, p4d_t p4dval)
{
	if (TRACE_PT_UPDATES > 1)
		trace_pt_update("set_p4d: p4dp 0x%lx, value 0x%lx\n", p4dp, p4d_val(p4dval));
	native_set_p4d(p4dp, p4dval);
}

static inline void set_p4d_at(struct mm_struct *mm, unsigned long addr, p4d_t *p4dp, p4d_t p4dval)
{
	trace_pt_update("set_p4d_at: mm 0x%lx, addr 0x%lx, p4dp 0x%lx, value 0x%lx\n",
			mm, addr, p4dp, p4d_val(p4dval));
	native_set_p4d(p4dp, p4dval);
}

static inline void p4d_clear(p4d_t *p4d)
{
	VM_BUG_ON(p4d_val(*p4d) & KERNEL_PT_MARK);
	p4d_val(*p4d) = _PAGE_INIT_VALID;
}

static inline void set_pgd_at(struct mm_struct *mm, unsigned long addr, pgd_t *pgdp, pgd_t pgdval)
{
	trace_pt_update("set_pgd_at: mm 0x%lx, addr 0x%lx, pgdp 0x%lx, value 0x%lx\n",
			mm, addr, pgdp, pgd_val(pgdval));
	native_set_pgd(pgdp, pgdval);
}

extern int memtype_reserve(phys_addr_t start, phys_addr_t end,
			   enum page_cache_mode memtype, bool *cache_flush_needed);
extern bool __must_check memtype_free_cacheflush(phys_addr_t start, phys_addr_t end);
extern void memtype_free(phys_addr_t start, phys_addr_t end);

#define MK_IOSPACE_PFN(space, pfn)	(pfn)
#define GET_IOSPACE(pfn)		0
#define GET_PFN(pfn)			(pfn)

#define NATIVE_VMALLOC_START	(NATIVE_KERNEL_IMAGE_AREA_BASE + \
							0x020000000000UL)
				/* 0x0000 e400 0000 0000 */
/* We need big enough vmalloc area since usage of pcpu_embed_first_chunk()
 * on e2k leads to having pcpu area span large ranges, and vmalloc area
 * should be able to span those same ranges (see pcpu_embed_first_chunk()). */
#define NATIVE_VMALLOC_END	(NATIVE_VMALLOC_START + 0x100000000000UL)
				/* 0x0000 f400 0000 0000 */
#define NATIVE_VMEMMAP_START	NATIVE_VMALLOC_END
				/* 0x0000 f400 0000 0000 */
#define NATIVE_VMEMMAP_END	(NATIVE_VMEMMAP_START + \
				 (1ULL << (E2K_MAX_PHYS_BITS - PAGE_SHIFT)) * \
						sizeof(struct page))
			/* 0x0000 f800 0000 0000 - for 64 bytes struct page */
			/* 0x0000 fc00 0000 0000 - for 128 bytes struct page */

/*
 * The module space starts from end of resident kernel image and
 * both areas should be within 2 ** 30 bits of the virtual addresses.
 */
#define MODULES_VADDR	E2K_MODULES_START
#define MODULES_END	E2K_MODULES_END

/* virtualization support */
#include <asm/kvm/pgtable.h>


#define pte_clear_not_present_full(mm, addr, ptep, fullmm) \
do { \
	u64 __pteval; \
	__pteval = _PAGE_INIT_VALID; \
	set_pte_not_present_at(mm, addr, ptep, __pte(__pteval)); \
} while (0)


#define pte_clear(mm, addr, ptep) \
do { \
	u64 __pteval; \
	__pteval = _PAGE_INIT_VALID; \
	set_pte_at(mm, addr, ptep, __pte(__pteval)); \
} while (0)

#if defined(CONFIG_SPARSEMEM) && defined(CONFIG_SPARSEMEM_VMEMMAP)
# define vmemmap	((struct page *)VMEMMAP_START)
#endif

#include <asm/pgd.h>

/*
 * ZERO_PAGE is a global shared page that is always zero: used
 * for zero-mapped memory areas etc..
 */
extern unsigned long	empty_zero_page[PAGE_SIZE / sizeof(unsigned long)];
extern struct page	*zeroed_page;
extern u64		zero_page_nid_to_pfn[MAX_NUMNODES];
extern struct page	*zero_page_nid_to_page[MAX_NUMNODES];

#define ZERO_PAGE(vaddr) zeroed_page

#define is_zero_pfn is_zero_pfn
static inline int is_zero_pfn(unsigned long pfn)
{
	int node;

#pragma loop count (4)
	for_each_node_state(node, N_MEMORY) {
		if (zero_page_nid_to_pfn[node] == pfn)
			return 1;
	}

	return 0;
}

#define my_zero_pfn my_zero_pfn
static inline u64 my_zero_pfn(unsigned long addr)
{
	return zero_page_nid_to_pfn[numa_node_id()];
}

extern void paging_init(void);

/* The pointer of kernel root-level page table directory. */
extern pgd_t swapper_pg_dir[PTRS_PER_PGD];

/*
 * The index and offset in the root-level page table directory.
 */
static inline pgd_t *node_pgd_offset_k(int nid, e2k_addr_t virt_addr)
{
	return mm_node_pgd(&init_mm, nid) + pgd_index(virt_addr);
}

/*
 * Encode and de-code a swap entry
 */
static inline unsigned long
mmu_get_swap_offset(swp_entry_t swap_entry, bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return get_swap_offset_v6(swap_entry);
	else
		return get_swap_offset_v3(swap_entry);
}

static inline swp_entry_t
mmu_create_swap_entry(unsigned long type, unsigned long offset, bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return create_swap_entry_v6(type, offset);
	else
		return create_swap_entry_v3(type, offset);
}

static inline pte_t
mmu_convert_swap_entry_to_pte(swp_entry_t swap_entry, bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return convert_swap_entry_to_pte_v6(swap_entry);
	else
		return convert_swap_entry_to_pte_v3(swap_entry);
}

static inline unsigned long __swp_offset(swp_entry_t swap_entry)
{
	return mmu_get_swap_offset(swap_entry, MMU_IS_PT_V6());
}

static inline swp_entry_t __swp_entry(unsigned long type, unsigned long offset)
{
	return mmu_create_swap_entry(type, offset, MMU_IS_PT_V6());
}

static inline pte_t __swp_entry_to_pte(swp_entry_t swap_entry)
{
	return mmu_convert_swap_entry_to_pte(swap_entry, MMU_IS_PT_V6());
}

static inline pmd_t __swp_entry_to_pmd(swp_entry_t swap_entry)
{
	return __pmd(pte_val(__swp_entry_to_pte(swap_entry)));
}

static inline pte_t
native_do_get_pte_for_address(struct vm_area_struct *vma, e2k_addr_t address)
{
	probe_entry_t	probe_pte;

	probe_pte = get_MMU_DTLB_ENTRY(address);
	if (DTLB_ENTRY_TEST_SUCCESSFUL(probe_entry_val(probe_pte)) &&
	    DTLB_ENTRY_TEST_VVA(probe_entry_val(probe_pte))) {
		return __pte(_PAGE_SET_PRESENT(probe_entry_val(probe_pte)));
	} else if (!DTLB_ENTRY_TEST_SUCCESSFUL(probe_entry_val(probe_pte))) {
		return __pte(0);
	} else {
		return __pte(probe_entry_val(probe_pte));
	}
}

extern int ptep_set_access_flags(struct vm_area_struct *vma,
				 unsigned long address, pte_t *ptep,
				 pte_t entry, int dirty);

#define p4d_addr_bound(addr)	(((addr) + P4D_SIZE) & P4D_MASK)
#define pud_addr_bound(addr)	(((addr) + PUD_SIZE) & PUD_MASK)
#define pmd_addr_bound(addr)	(((addr) + PMD_SIZE) & PMD_MASK)

/* interface functions to handle some things on the PT level */
void split_simple_pmd_page(pgprot_t *ptp, pte_t *ptes);
void map_pud_huge_page_to_simple_pmds(pgprot_t *pmd_page, e2k_addr_t phys_page,
				      pgprot_t pgprot);

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
extern int pmdp_set_access_flags(struct vm_area_struct *vma,
				 unsigned long address, pmd_t *pmdp,
				 pmd_t entry, int dirty);
extern int pudp_set_access_flags(struct vm_area_struct *vma,
				 unsigned long address, pud_t *pudp,
				 pud_t entry, int dirty);
#else /* !CONFIG_TRANSPARENT_HUGEPAGE */
static inline int pmdp_set_access_flags(struct vm_area_struct *vma,
					unsigned long address, pmd_t *pmdp,
					pmd_t entry, int dirty)
{
	BUILD_BUG();
	return 0;
}

static inline int pudp_set_access_flags(struct vm_area_struct *vma,
					unsigned long address, pud_t *pudp,
					pud_t entry, int dirty)
{
	BUILD_BUG();
	return 0;
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

#ifdef CONFIG_NUMA
int kernel_image_duplicate_page_range(void *addr, size_t size,
				      bool page_tables_only);
#else
static inline int kernel_image_duplicate_page_range(void *addr, size_t size,
						    bool page_tables_only)
{
	return 0;
}
#endif

#ifdef CONFIG_E2K_MODULES_DUPLICATION
int duplicate_preallocated_pgds_for_modules_area(void);
int duplicate_pgds_for_modules_area(void);
int duplicate_module_pages(void *addr, size_t size, struct list_head *duplicated_pages);
void deduplicate_module_pages(void *addr, size_t size, struct list_head *duplicated_pages);
#else /* !CONFIG_E2K_MODULES_DUPLICATION */
static inline int duplicate_module_pages(void *addr, size_t size,
					 struct list_head *duplicated_pages)
{
	return 0;
}
static inline void deduplicate_module_pages(void *addr, size_t size,
					    struct list_head *duplicated_pages)
{
}
#endif /* CONFIG_E2K_MODULES_DUPLICATION */

/* atomic versions of the some PTE manipulations */
#include <asm/pgtable-atomic.h>

#define flush_tlb_fix_spurious_fault(vma, address)	do { } while (0)

#define __HAVE_PHYS_MEM_ACCESS_PROT
struct file;
extern pgprot_t phys_mem_access_prot(struct file *file, unsigned long pfn,
				     unsigned long size, pgprot_t vma_prot);

#define __HAVE_ARCH_FLUSH_PMD_TLB_RANGE
#define __HAVE_ARCH_PTEP_SET_ACCESS_FLAGS
#define __HAVE_ARCH_PMDP_SET_ACCESS_FLAGS
#define __HAVE_ARCH_PTE_CLEAR_NOT_PRESENT_FULL
#define __HAVE_ARCH_PTEP_TEST_AND_CLEAR_YOUNG
#define __HAVE_ARCH_PTEP_GET_AND_CLEAR
#define __HAVE_ARCH_PTEP_SET_WRPROTECT
#define __HAVE_ARCH_PMDP_TEST_AND_CLEAR_YOUNG
#define __HAVE_ARCH_PMDP_SET_WRPROTECT
#define __HAVE_ARCH_PMDP_HUGE_GET_AND_CLEAR
#define __HAVE_ARCH_PUDP_HUGE_GET_AND_CLEAR
#define __HAVE_PFNMAP_TRACKING

#ifdef CONFIG_HAVE_ARCH_USERFAULTFD_WP
static inline int pte_uffd_wp(pte_t pte)
{
	return test_pte_val_flags(pte_val(pte), UNI_PAGE_UFFD_WP);
}

static inline pte_t pte_mkuffd_wp(pte_t pte)
{
	return __pte(set_pte_val_flags(pte_val(pte), UNI_PAGE_UFFD_WP));
}

static inline pte_t pte_clear_uffd_wp(pte_t pte)
{
	return __pte(clear_pte_val_flags(pte_val(pte), UNI_PAGE_UFFD_WP));
}

static inline int pmd_uffd_wp(pmd_t pmd)
{
	return test_pte_val_flags(pmd_val(pmd), UNI_PAGE_UFFD_WP);
}

static inline pmd_t pmd_mkuffd_wp(pmd_t pmd)
{
	return __pmd(set_pte_val_flags(pmd_val(pmd), UNI_PAGE_UFFD_WP));
}

static inline pmd_t pmd_clear_uffd_wp(pmd_t pmd)
{
	return __pmd(clear_pte_val_flags(pmd_val(pmd), UNI_PAGE_UFFD_WP));
}

static inline int pte_swp_uffd_wp(pte_t pte)
{
	return test_pte_val_flags(pte_val(pte), UNI_PAGE_SWP_UFFD_WP);
}

static inline pte_t pte_swp_mkuffd_wp(pte_t pte)
{
	return __pte(set_pte_val_flags(pte_val(pte), UNI_PAGE_SWP_UFFD_WP));
}

static inline pte_t pte_swp_clear_uffd_wp(pte_t pte)
{
	return __pte(clear_pte_val_flags(pte_val(pte), UNI_PAGE_SWP_UFFD_WP));
}

static inline int pmd_swp_uffd_wp(pmd_t pmd)
{
	return test_pte_val_flags(pmd_val(pmd), UNI_PAGE_SWP_UFFD_WP);
}

static inline pmd_t pmd_swp_mkuffd_wp(pmd_t pmd)
{
	return __pmd(set_pte_val_flags(pmd_val(pmd), UNI_PAGE_SWP_UFFD_WP));
}

static inline pmd_t pmd_swp_clear_uffd_wp(pmd_t pmd)
{
	return __pmd(clear_pte_val_flags(pmd_val(pmd), UNI_PAGE_SWP_UFFD_WP));
}
#endif /* CONFIG_HAVE_ARCH_USERFAULTFD_WP */

static inline char *pte_mem_type_name(enum pte_mem_type type)
{
	switch (type) {
	case GEN_CACHE_MT:
		return "GC";
	case GEN_NON_CACHE_MT:
		return "GnC";
	case EXT_PREFETCH_MT:
		return "XP";
	case EXT_NON_PREFETCH_MT:
		return "XnP";
	case EXT_CONFIG_MT:
		return "XC";
	case GEN_NON_CACHE_ORDERED_MT:
		return "GnC_ordered";
	}
	BUG();
}

static inline bool pte_mem_type_is_coherent(enum pte_mem_type type)
{
	switch (type) {
	case GEN_CACHE_MT:
	case GEN_NON_CACHE_MT:
		return true;
	case EXT_NON_PREFETCH_MT:
	case EXT_CONFIG_MT:
		return false;
	case EXT_PREFETCH_MT:
		return !cpu_has(CPU_FEAT_ISET_V6);
	case GEN_NON_CACHE_ORDERED_MT:
		return cpu_has(CPU_FEAT_ISET_V6);
	}
	BUG();
}

#endif /* !(_E2K_PGTABLE_H) */
