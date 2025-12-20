/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * E2K page table operations.
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
#include <linux/topology.h>

#include <asm/pgtable_def.h>
#include <asm/system.h>
#include <asm/cpu_regs_access.h>
#include <asm/head.h>
#include <asm/bitops.h>
#include <asm/machdep.h>
#include <asm/secondary_space.h>
#include <asm/mmu_regs_access.h>
#include <asm/tlb_regs_access.h>
#include <asm/pgatomic.h>

#include <asm/5level-fixup.h>

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

#define validate_pgd_at(mm, addr, pgdp)	\
		set_pgd_at(mm, addr, pgdp, __pgd(_PAGE_INIT_VALID))

#define	get_pte_for_address(vma, address) \
		native_do_get_pte_for_address(vma, address)

#define pgd_clear_kernel(pgdp)		(pgd_val(*(pgdp)) = 0UL)
#define pud_clear_kernel(pudp)		(pud_val(*(pudp)) = 0UL)
#define pmd_clear_kernel(pmdp)		(pmd_val(*(pmdp)) = 0UL)
#define pte_clear_kernel(ptep)		(pte_val(*(ptep)) = 0UL)

/* pte_page() returns the 'struct page *' corresponding to the PTE: */
#define pte_page(pte) pfn_to_page(pte_pfn(pte))
#define pmd_page(pmd) pfn_to_page(pmd_pfn(pmd))
#define pud_page(pud) pfn_to_page(pud_pfn(pud))
#define pgd_page(pgd) pfn_to_page(pgd_pfn(pgd))


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

static inline pmd_t *pud_pgtable(pud_t pud)
{
	return (pmd_t *) __va(_PAGE_PFN_TO_PADDR(pud_val(pud)));
}

static inline unsigned long pgd_page_vaddr(pgd_t pgd)
{
	return (unsigned long) __va(_PAGE_PFN_TO_PADDR(pgd_val(pgd)));
}

#define pud_set_k(pudp, pmdp)		(*(pudp) = mk_pud_addr(pmdp, \
							PAGE_KERNEL_PMD))
#define pud_set_u(pudp, pmdp)		(*(pudp) = mk_pud_addr(pmdp, \
							PAGE_USER_PMD))

#define mk_pgd_phys_k(pudp)		mk_pgd_addr(pudp, PAGE_KERNEL_PUD)

#define vmlpt_pgd_set(pgdp, lpt)	pgd_set_u(pgdp, (pud_t *)(lpt))
#define pgd_set_k(pgdp, pudp)		(*(pgdp) = mk_pgd_phys_k(pudp))
#define pgd_set_u(pgdp, pudp)		(*(pgdp) = mk_pgd_addr(pudp, \
							PAGE_USER_PUD))


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
	__flush_icache_range(address, address + PTE_SIZE);
}

static inline void flush_pmd_from_ic(pmd_t val)
{
	unsigned long address;

	address = (unsigned long) __va(_PAGE_PFN_TO_PADDR(pmd_val(val)));
	__flush_icache_range(address, address + PMD_SIZE);
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

static inline void native_set_pgd(pgd_t *pgdp, pgd_t pgdval)
{
	*pgdp = pgdval;
}
#else
# define native_set_pte(ptep, pteval, known_not_present) (*(ptep) = (pteval))
# define native_set_pmd(pmdp, pmdval)	(*(pmdp) = (pmdval))
# define native_set_pud(pudp, pudval)	(*(pudp) = (pudval))
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

static inline void set_pte_not_present_at(struct mm_struct *mm,
		 unsigned long addr, pte_t *ptep, pte_t pteval)
{
	trace_pt_update("set_pte_not_present_at: mm 0x%lx, addr 0x%lx, ptep 0x%lx, value 0x%lx\n",
			mm, addr, ptep, pte_val(pteval));
	native_set_pte(ptep, pteval, true);
}

static inline void set_pmd(pmd_t *pmdp, pmd_t pmdval)
{
	if (TRACE_PT_UPDATES > 1)
		trace_pt_update("set_pmd: pmdp 0x%lx, value 0x%lx\n",
				pmdp, pmd_val(pmdval));
	native_set_pmd(pmdp, pmdval);
}

static inline void set_pmd_at(struct mm_struct *mm, unsigned long addr,
			      pmd_t *pmdp, pmd_t pmdval)
{
	trace_pt_update("set_pmd_at: mm 0x%lx, addr 0x%lx, pmdp 0x%lx, value 0x%lx\n", \
			mm, addr, pmdp, pmd_val(pmdval));
	native_set_pmd(pmdp, pmdval);
}

static inline void pmd_clear(pmd_t *pmdp)
{
	trace_pt_update("pmd_clear: pmdp 0x%lx, value 0x%lx\n",
			pmdp, _PAGE_INIT_VALID);
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
	trace_pt_update("set_pud_at: mm 0x%lx, addr 0x%lx, pudp 0x%lx, value 0x%lx\n", \
			mm, addr, pudp, pud_val(pudval));
	native_set_pud(pudp, pudval);
}

static inline void pud_clear(pud_t *pudp)
{
	trace_pt_update("pud_clear: pudp 0x%lx, value 0x%lx\n",
			pudp, _PAGE_INIT_VALID);
	native_set_pud(pudp, __pud(_PAGE_INIT_VALID));
}

static inline void set_pgd(pgd_t *pgdp, pgd_t pgdval)
{
	if (TRACE_PT_UPDATES > 1)
		trace_pt_update("set_pgd: pgdp 0x%lx, value 0x%lx\n",
				pgdp, pgd_val(pgdval));
	native_set_pgd(pgdp, pgdval);
}

static inline void set_pgd_at(struct mm_struct *mm, unsigned long addr,
			      pgd_t *pgdp, pgd_t pgdval)
{
	trace_pt_update("set_pgd_at: mm 0x%lx, addr 0x%lx, pgdp 0x%lx, value 0x%lx\n",
			mm, addr, pgdp, pgd_val(pgdval));
	native_set_pgd(pgdp, pgdval);
}

static inline void pgd_clear(pgd_t *pgd)
{
	pgd_val(*pgd) = _PAGE_INIT_VALID;
}

/*
 * Remap I/O pages at `pfn' of size `size' with page protection
 * `prot' into virtual address `from'.
 *
 * This function is used only on device memory and track_pfn_remap()
 * will explicitly set "External" memory type.
 *
 * As for remap_pfn_range(), it unfortunately can be used with anything,
 * so we rely on track_pfn_remap to check pfn and assign proper memory type:
 * https://lkml.org/lkml/2006/3/16/170
 *
 * "
 * remap_pfn_range() doesn't muck around with "struct page" AT ALL, so you
 * can pass it damn well anything you want these days. It doesn't care,
 * the VM doesn't care, there's no ref-counting or page flag checking
 * either on the mmap or the munmap parh.
 *
 * Normally, you'd use remap_pfn_range() only for special allocations.
 * Most commonly, it's not RAM at all, but the PCI MMIO memory window to
 * the hardware itself.
 * "
 */
#define io_remap_pfn_range io_remap_pfn_range
extern int io_remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
		unsigned long pfn, unsigned long size, pgprot_t prot);

extern int memtype_reserve(phys_addr_t start, phys_addr_t end,
			   enum page_cache_mode memtype, bool *cache_flush_needed);
extern bool __must_check memtype_free_cacheflush(phys_addr_t start, phys_addr_t end);
extern void memtype_free(phys_addr_t start, phys_addr_t end);

extern int track_pfn_copy(struct vm_area_struct *vma);
extern int track_pfn_remap(struct vm_area_struct *vma, pgprot_t *prot,
		unsigned long pfn, unsigned long addr, unsigned long size);
extern void track_pfn_insert(struct vm_area_struct *vma, pgprot_t *prot, pfn_t pfn);
extern void untrack_pfn(struct vm_area_struct *vma, unsigned long pfn,
			unsigned long size);
extern void untrack_pfn_moved(struct vm_area_struct *vma);

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
#define MODULES_VADDR	E2K_MODULES_START	/* 0x0000 e200 0xxx x000 */
#define MODULES_END	E2K_MODULES_END		/* 0x0000 e200 4000 0000 */

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
extern unsigned long	empty_zero_page[PAGE_SIZE/sizeof(unsigned long)];
extern struct page	*zeroed_page;
extern u64		zero_page_nid_to_pfn[MAX_NUMNODES];
extern struct page	*zero_page_nid_to_page[MAX_NUMNODES];

#define ZERO_PAGE(vaddr) zeroed_page

#define is_zero_pfn is_zero_pfn
static inline int is_zero_pfn(unsigned long pfn)
{
	int node;

#pragma loop count (4)
	for_each_node_state(node, N_MEMORY)
		if (zero_page_nid_to_pfn[node] == pfn)
			return 1;

	return 0;
}

#define my_zero_pfn my_zero_pfn
static inline u64 my_zero_pfn(unsigned long addr)
{
	return zero_page_nid_to_pfn[numa_node_id()];
}

static inline int is_zero_page(struct page *page)
{
	int node;

#pragma loop count (4)
	for_each_node_state(node, N_MEMORY)
		if (zero_page_nid_to_page[node] == page)
			return 1;

	return 0;
}

extern	void paging_init(void);

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
 * The index and offset in the upper page table directory.
 */
#define pud_offset(dir, address)	((pud_t *)pgd_page_vaddr(*(dir)) + \
						pud_index(address))

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

#define pgd_addr_bound(addr)	(((addr) + PGDIR_SIZE) & PGDIR_MASK)
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
#else	/* !CONFIG_TRANSPARENT_HUGEPAGE */
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

#endif /* !(_E2K_PGTABLE_H) */
