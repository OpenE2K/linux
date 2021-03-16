/*
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

#include <asm/pgtable_def.h>
#include <asm/system.h>
#include <asm/cpu_regs_access.h>
#include <asm/head.h>
#include <asm/bitops.h>
#include <asm/p2v/boot_head.h>
#include <asm/machdep.h>
#include <asm/secondary_space.h>
#include <asm/mmu_regs_access.h>
#include <asm/tlb_regs_access.h>
#include <asm/pgatomic.h>

#include <asm-generic/5level-fixup.h>

/*
 * The defines and routines to manage and access the four-level
 * page table.
 */

#define	set_pte(ptep, pteval) \
		native_set_pte(ptep, pteval, false)
#define set_pte_at(mm, addr, ptep, pteval) \
		native_set_pte(ptep, pteval, false)
#define set_pte_not_present_at(mm, addr, ptep, pteval) \
		native_set_pte(ptep, pteval, true)
#define set_pte_to_move_at(mm, addr, ptep, pteval) \
		native_set_pte_to_move(ptep, pteval)
#define validate_pte_at(mm, addr, ptep, pteval) \
		native_set_pte_noflush(ptep, pteval)
#define	ptep_get_and_clear_to_move(mm, addr, ptep) \
		ptep_get_and_clear(mm, addr, ptep)
#define	boot_set_pte_at(addr, ptep, pteval)	\
		native_set_pte(ptep, pteval, false)
#define	boot_set_pte_kernel(addr, ptep, pteval)	\
		boot_set_pte_at(addr, ptep, pteval)

#define	set_pmd(pmdp, pmdval) \
		native_set_pmd(pmdp, pmdval)
#define set_pmd_at(mm, addr, pmdp, pmdval) \
({ \
	(void)(mm); \
	(void)(addr); \
	native_set_pmd(pmdp, pmdval); \
})
#define validate_pmd_at(mm, addr, pmdp, pmdval)	\
		native_set_pmd_noflush(pmdp, pmdval)

#define	set_pud(pudp, pudval) \
		native_set_pud(pudp, pudval)
#define set_pud_at(mm, addr, pudp, pudval) \
		native_set_pud(pudp, pudval)
#define validate_pud_at(mm, addr, pudp)	\
		set_pud_at(mm, addr, pudp, __pud(_PAGE_INIT_VALID))
#define invalidate_pud_at(mm, addr, pudp)	\
		set_pud_at(mm, addr, pudp, __pud(0))

#define	set_pgd(pgdp, pgdval) \
		native_set_pgd(pgdp, pgdval)
#define set_pgd_at(mm, addr, pgdp, pgdval) \
		native_set_pgd(pgdp, pgdval)
#define validate_pgd_at(mm, addr, pgdp)	\
		set_pgd_at(mm, addr, pgdp, __pgd(_PAGE_INIT_VALID))
#define invalidate_pgd_at(mm, addr, pgdp)	\
		set_pgd_at(mm, addr, pgdp, __pgd(0))

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


#define	boot_pte_page(pte)	\
		(e2k_addr_t)boot_va(_PAGE_PFN_TO_PADDR(pte_val(pte)))

#define pmd_set_k(pmdp, ptep)	(*(pmdp) = mk_pmd_addr(ptep, \
							PAGE_KERNEL_PTE))
#define pmd_set_u(pmdp, ptep)	(*(pmdp) = mk_pmd_addr(ptep, \
							PAGE_USER_PTE))
#define pmd_clear(pmdp) \
do { \
	u64 __pmdval; \
	__pmdval = (test_ts_flag(TS_KEEP_PAGES_VALID)) ? \
					_PAGE_INIT_VALID : 0UL; \
	native_set_pmd(pmdp, __pmd(__pmdval)); \
} while (0)

static inline unsigned long pmd_page_vaddr(pmd_t pmd)
{
	return (unsigned long)__va(_PAGE_PFN_TO_PADDR(pmd_val(pmd)));
}

static inline unsigned long pud_page_vaddr(pud_t pud)
{
	return (unsigned long)__va(_PAGE_PFN_TO_PADDR(pud_val(pud)));
}

static inline unsigned long pgd_page_vaddr(pgd_t pgd)
{
	return (unsigned long)__va(_PAGE_PFN_TO_PADDR(pgd_val(pgd)));
}


#define boot_pmd_set_k(pmdp, ptep)	\
		(*(pmdp) = mk_pmd_phys(boot_vpa_to_pa((e2k_addr_t)(ptep)), \
							PAGE_KERNEL_PTE))
#define boot_pmd_set_u(pmdp, ptep)	\
		(*(pmdp) = mk_pmd_phys(boot_vpa_to_pa((e2k_addr_t)(ptep)), \
							PAGE_USER_PTE))
#define	boot_pmd_page(pmd)		\
		(e2k_addr_t)boot_va(_PAGE_PFN_TO_PADDR(pmd_val(pmd)))

#define pud_set_k(pudp, pmdp)		(*(pudp) = mk_pud_addr(pmdp, \
							PAGE_KERNEL_PMD))
#define pud_set_u(pudp, pmdp)		(*(pudp) = mk_pud_addr(pmdp, \
							PAGE_USER_PMD))
static inline void pud_clear(pud_t *pud)
{
	pud_val(*pud) = (test_ts_flag(TS_KEEP_PAGES_VALID)) ?
						_PAGE_INIT_VALID : 0UL;
}

#define boot_pud_set_k(pudp, pmdp)	\
		(*(pudp) = mk_pud_phys(boot_vpa_to_pa((e2k_addr_t)(pmdp)), \
							PAGE_KERNEL_PMD))
#define boot_pud_set_u(pudp, pmdp)	\
		(*(pudp) = mk_pud_phys(boot_vpa_to_pa((e2k_addr_t)(pmdp)), \
							PAGE_USER_PMD))
#define	boot_pud_page(pud)		\
		(e2k_addr_t)boot_va(_PAGE_PFN_TO_PADDR(pud_val(pud)))

#define mk_pgd_phys_k(pudp)		mk_pgd_addr(pudp, PAGE_KERNEL_PUD)

#ifndef	CONFIG_NUMA
#define pgd_set_k(pgdp, pudp)		(*(pgdp) = mk_pgd_phys_k(pudp))
#define	node_pgd_set_k(nid, pgdp, pudp)	pgd_set_k(pgdp, pudp)
#else	/* CONFIG_NUMA */
extern void node_pgd_set_k(int nid, pgd_t *pgdp, pud_t *pudp);
static void inline pgd_set_k(pgd_t *pgdp, pud_t *pudp)
{
	node_pgd_set_k(numa_node_id(), pgdp, pudp);
}
#endif	/* ! CONFIG_NUMA */

#define vmlpt_pgd_set(pgdp, lpt)	pgd_set_u(pgdp, (pud_t *)(lpt))
#define pgd_set_u(pgdp, pudp)		(*(pgdp) = mk_pgd_addr(pudp, \
							PAGE_USER_PUD))
static inline void pgd_clear_one(pgd_t *pgd)
{
	pgd_val(*pgd) = (test_ts_flag(TS_KEEP_PAGES_VALID)) ?
						_PAGE_INIT_VALID : 0UL;
}


#define boot_mk_pgd_phys_k(pudp)	\
		mk_pgd_phys(boot_vpa_to_pa((e2k_addr_t)(pudp)), PAGE_KERNEL_PUD)
#define boot_mk_pgd_phys_u(pudp)	\
		mk_pgd_phys(boot_vpa_to_pa((e2k_addr_t)(pudp)), PAGE_USER_PUD)
#ifndef	CONFIG_NUMA
#define boot_pgd_set_k(pgdp, pudp)	(*(pgdp) = boot_mk_pgd_phys_k(pudp))
#define boot_pgd_set_u(pgdp, pudp)	(*(pgdp) = boot_mk_pgd_phys_u(pudp))

#else	/* CONFIG_NUMA */
extern void boot_pgd_set(pgd_t *my_pgdp, pud_t *pudp, int user);
#define boot_pgd_set_k(pgdp, pudp)	boot_pgd_set(pgdp, pudp, 0)
#define boot_pgd_set_u(pgdp, pudp)	boot_pgd_set(pgdp, pudp, 1)
#endif	/* ! CONFIG_NUMA */

#define boot_vmlpt_pgd_set(pgdp, lpt)	(*(pgdp) = boot_mk_pgd_phys_k(	\
							(pud_t *)(lpt)))
#define	boot_pgd_page(pgd)		\
		(e2k_addr_t)boot_va(_PAGE_PFN_TO_PADDR(pgd_val(pgd)))

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
		int have_flush_dc_ic = cpu_has(CPU_FEAT_FLUSH_DC_IC);
		pte_t oldpte = *ptep;

		*ptep = pteval;

		if (have_flush_dc_ic && pte_present_and_exec(oldpte) &&
				(!pte_present_and_exec(pteval) ||
				 pte_pfn(oldpte) != pte_pfn(pteval)))
			flush_pte_from_ic(oldpte);
	}
}

static inline void native_set_pte_to_move(pte_t *ptep, pte_t pteval)
{
	native_set_pte(ptep, pteval, false);
}

static inline void native_set_pmd(pmd_t *pmdp, pmd_t pmdval)
{
	int have_flush_dc_ic = cpu_has(CPU_FEAT_FLUSH_DC_IC);
	pmd_t oldpmd = *pmdp;

	*pmdp = pmdval;

	if (have_flush_dc_ic && pmd_present_and_exec_and_huge(oldpmd) &&
			(!pmd_present_and_exec_and_huge(pmdval) ||
			 pmd_pfn(oldpmd) != pmd_pfn(pmdval)))
		flush_pmd_from_ic(oldpmd);
}

static inline void native_set_pud(pud_t *pudp, pud_t pudval)
{
	int have_flush_dc_ic = cpu_has(CPU_FEAT_FLUSH_DC_IC);
	pud_t oldpud = *pudp;

	*pudp = pudval;

	if (have_flush_dc_ic && pud_present_and_exec_and_huge(oldpud) &&
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
# define native_set_pte_to_move(ptep, pteval) native_set_pte(ptep, pteval, false)
# define native_set_pmd(pmdp, pmdval)	(*(pmdp) = (pmdval))
# define native_set_pud(pudp, pudval)	(*(pudp) = (pudval))
# define native_set_pgd(pgdp, pgdval)	(*(pgdp) = (pgdval))
#endif

/*
 * Remap I/O pages at `pfn' of size `size' with page protection
 * `prot' into virtual address `from'.
 *
 * This function is used only on device memory and track_pfn_remap()
 * will explicitly set "External" memory type.
 *
 * And remap_pfn_range() should be used on RAM only and not on device
 * memory, but in practice many drivers violate API and just use
 * remap_pfn_range() everywhere.  In this case track_pfn_remap() will
 * determine the required type. */
#define io_remap_pfn_range(vma, addr, pfn, size, prot) \
({ \
	unsigned long __irp_pfn = (pfn); \
	VM_WARN_ON_ONCE(pfn_valid(__irp_pfn)); \
	remap_pfn_range((vma), (addr), (pfn), (size), (prot)); \
})

/*
 * track_pfn_remap is called when a _new_ pfn mapping is being established
 * by remap_pfn_range() for physical range indicated by pfn and size.
 */
extern int track_pfn_remap(struct vm_area_struct *vma, pgprot_t *prot,
		unsigned long pfn, unsigned long addr, unsigned long size);

/*
 * track_pfn_insert is called when a _new_ single pfn is established
 * by vm_insert_pfn().
 *
 * This does not cover vm_insert_page so if some bad driver decides
 * to use it on I/O memory we could get into trouble.
 */
extern void track_pfn_insert(struct vm_area_struct *vma, pgprot_t *prot, pfn_t pfn);

/*
 * track_pfn_copy is called when vma that is covering the pfnmap gets
 * copied through copy_page_range().
 */
static inline int track_pfn_copy(struct vm_area_struct *vma)
{
	return 0;
}

/*
 * untrack_pfn is called while unmapping a pfnmap for a region.
 * untrack can be called for a specific region indicated by pfn and size or
 * can be for the entire vma (in which case pfn, size are zero).
 */
static inline void untrack_pfn(struct vm_area_struct *vma,
			       unsigned long pfn, unsigned long size)
{
}

/*
 * untrack_pfn_moved is called while mremapping a pfnmap for a new region.
 */
static inline void untrack_pfn_moved(struct vm_area_struct *vma)
{
}
#define MK_IOSPACE_PFN(space, pfn)	(pfn)
#define GET_IOSPACE(pfn)		0
#define GET_PFN(pfn)			(pfn)

#ifndef __ASSEMBLY__

#define NATIVE_VMALLOC_START	(NATIVE_KERNEL_IMAGE_AREA_BASE + \
							0x020000000000UL)
				/* 0x0000 e400 0000 0000 */
#define NATIVE_VMALLOC_END	(NATIVE_VMALLOC_START + 0x010000000000UL)
				/* 0x0000 e500 0000 0000 */
#define NATIVE_VMEMMAP_START	(NATIVE_VMALLOC_END +   0x010000000000UL)
				/* 0x0000 e600 0000 0000 */
#define NATIVE_VMEMMAP_END	(NATIVE_VMEMMAP_START + \
					(1ULL << (E2K_MAX_PHYS_BITS - \
						PAGE_SHIFT)) * \
							sizeof(struct page))

#ifdef CONFIG_SMP
static inline void
ptep_wrprotect_atomic(struct mm_struct *mm,
				unsigned long addr, pte_t *ptep)
{
	pt_set_wrprotect_atomic(mm, addr, (pgprot_t *)ptep);
}
#else	/* ! CONFIG_SMP */
static inline void
ptep_wrprotect_atomic(struct mm_struct *mm,
				unsigned long addr, pte_t *ptep)
{
}
#endif /* CONFIG_SMP */

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
	__pteval = (test_ts_flag(TS_KEEP_PAGES_VALID)) ? \
					_PAGE_INIT_VALID : 0UL; \
	set_pte_not_present_at(mm, addr, ptep, __pte(__pteval)); \
} while (0)


#define pte_clear(mm, addr, ptep) \
do { \
	u64 __pteval; \
	__pteval = (test_ts_flag(TS_KEEP_PAGES_VALID)) ? \
					_PAGE_INIT_VALID : 0UL; \
	set_pte_at(mm, addr, ptep, __pte(__pteval)); \
} while (0)

#if !defined(CONFIG_BOOT_E2K) && !defined(E2K_P2V)
static inline pte_t
do_ptep_get_and_clear(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
	int have_flush_dc_ic = cpu_has(CPU_FEAT_FLUSH_DC_IC);
	int mm_users;
	pte_t oldpte;
	prefetch_offset(ptep, PREFETCH_STRIDE);
# ifdef CONFIG_SMP
	u64 newval;

	newval = (test_ts_flag(TS_KEEP_PAGES_VALID)) ?
					_PAGE_INIT_VALID : 0UL;

	oldpte = __pte(pt_get_and_xchg_atomic(mm, addr, newval,
						(pgprot_t *)ptep));
# else
	oldpte = *ptep;
	pte_clear(mm, addr, ptep);
# endif

	if (likely(mm != NULL))
		mm_users = (atomic_read(&mm->mm_users) != 0);
	else
		/* kernel or guest process: users exist always */
		mm_users = true;

	/* mm_users check is for the fork() case: we do not
	 * want to spend time flushing when we are exiting. */
	if (have_flush_dc_ic && mm_users && pte_present_and_exec(oldpte))
		flush_pte_from_ic(oldpte);

	return oldpte;
}

static inline pte_t
do_ptep_get_and_clear_as_valid(struct mm_struct *mm,
				unsigned long addr, pte_t *ptep)
{
	int have_flush_dc_ic = cpu_has(CPU_FEAT_FLUSH_DC_IC);
	pte_t oldpte;

	prefetch_offset(ptep, PREFETCH_STRIDE);
# ifdef CONFIG_SMP
	oldpte = __pte(pt_get_and_clear_atomic(mm, addr, (pgprot_t *)ptep));
# else
	oldpte = *ptep;
	pte_val(*ptep) &= _PAGE_INIT_VALID;
# endif

	if (have_flush_dc_ic && pte_present_and_exec(oldpte))
		flush_pte_from_ic(oldpte);

	return oldpte;
}
#else
static inline pte_t
do_ptep_get_and_clear(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
	prefetch_offset(ptep, PREFETCH_STRIDE);
# ifdef CONFIG_SMP
	return __pte(pt_get_and_xchg_atomic(mm, addr, 0UL, (pgprot_t *)ptep));
# else
	pte_t pte = *ptep;
	pte_clear(mm, addr, ptep);
	return pte;
# endif
}

static inline pte_t
do_ptep_get_and_clear_as_valid(struct mm_struct *mm,
				unsigned long addr, pte_t *ptep)
{
	pte_t oldpte;

	prefetch_offset(ptep, PREFETCH_STRIDE);
# ifdef CONFIG_SMP
	oldpte = __pte(pt_get_and_clear_atomic(mm, addr, (pgprot_t *)ptep));
# else
	oldpte = *ptep;
	pte_val(*ptep) &= _PAGE_INIT_VALID;
# endif

	return oldpte;
}
#endif

static inline pte_t
ptep_get_and_clear(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
	return do_ptep_get_and_clear(mm, addr, ptep);
}

static inline pte_t
ptep_get_and_clear_as_valid(struct mm_struct *mm, unsigned long addr,
				pte_t *ptep)
{
	return do_ptep_get_and_clear_as_valid(mm, addr, ptep);
}

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

extern	void paging_init(void);

/*
 * The index and offset in the root-level page table directory.
 */
/* to find an entry in a kernel root page-table-directory */
#define pgd_offset_k(virt_addr)		((pgd_t *)kernel_root_pt + 	\
						pgd_index(virt_addr))
#define boot_pgd_offset_k(virt_addr)	((pgd_t *)boot_root_pt +	\
						boot_pgd_index(virt_addr))
#ifdef	CONFIG_NUMA
extern pgd_t *node_pgd_offset_kernel(int nid, e2k_addr_t virt_addr);
#else	/* ! CONFIG_NUMA */
#define node_pgd_offset_kernel(nid, virt_addr)	\
({						\
	(nid);					\
	pgd_offset_k(virt_addr);		\
})
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

	if (MMU_IS_SEPARATE_PT())
		/* CPU pgd is not user and user pgds do not copy to some */
		/* other PGDs */
		return 0;
	if (!THERE_IS_DUP_KERNEL)
		return 0;
	if (!current->active_mm || current->active_mm->pgd != pgd_table)
		return 0;
	pgd_ind = pgd_to_index(pgd);
	cpu_pgd = &cpu_kernel_root_pt[pgd_ind];
	if (pgd_none(*cpu_pgd)) {
		pr_err("%s(): CPU #%u kernel root pgd %px already clean 0x%lx\n",
			__func__, raw_smp_processor_id(),
			cpu_pgd, pgd_val(*cpu_pgd));
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
#define pud_offset(dir, address)	((pud_t *)pgd_page_vaddr(*(dir)) + \
						pud_index(address))

/*
 * The index and offset in the middle page table directory
 */
#define pmd_offset(pud, address)	((pmd_t *) pud_page_vaddr(*(pud)) + \
						pmd_index(address))

/*
 * The index and offset in the third-level page table.
 */
#define pte_offset_kernel(pmd, address)	\
		((pte_t *) pmd_page_vaddr(*(pmd)) + pte_index(address))
#define pte_offset_map(pmd, address) \
({ \
	pte_t *__pom_pte = pte_offset_kernel((pmd), (address)); \
	prefetchw(__pom_pte); \
	__pom_pte; \
})

#define pte_unmap(pte)		do { } while (0)

#define	boot_pte_index(virt_addr)	pte_index(virt_addr)
#define boot_pte_offset(pmdp, addr)	((pte_t *)boot_pmd_page(*(pmdp)) + \
						boot_pte_index(addr))

/*
 * Encode and de-code a swap entry
 */
static inline unsigned long
mmu_get_swap_offset(swp_entry_t swap_entry, bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return get_swap_offset_v6(swap_entry);
	else
		return get_swap_offset_v2(swap_entry);
}
static inline swp_entry_t
mmu_create_swap_entry(unsigned long type, unsigned long offset, bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return create_swap_entry_v6(type, offset);
	else
		return create_swap_entry_v2(type, offset);
}
static inline pte_t
mmu_convert_swap_entry_to_pte(swp_entry_t swap_entry, bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return convert_swap_entry_to_pte_v6(swap_entry);
	else
		return convert_swap_entry_to_pte_v2(swap_entry);
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

/*
 * atomic versions of the some PTE manipulations:
 */
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

#ifdef CONFIG_SMP
static inline int 
test_and_clear_relaxed(pgprotval_t mask, pgprot_t *addr)
{
	pgprotval_t retval;

	retval = pt_clear_relaxed_atomic(mask, addr);

	return (retval & mask) != 0;
}
#endif /* CONFIG_SMP */

static inline int
ptep_test_and_clear_young(struct vm_area_struct *vma, unsigned long addr,
				pte_t *ptep)
{
	pte_t pte;

	prefetch_offset(ptep, PREFETCH_STRIDE);

#ifdef CONFIG_SMP
	pte_val(pte) = pt_clear_young_atomic(vma->vm_mm, addr,
						(pgprot_t *)ptep);
	return pte_young(pte);
#else
	pte = *ptep;
	if (!pte_young(pte))
		return 0;
	set_pte_at(vma->vm_mm, addr, ptep, pte_mkold(pte));
	return 1;
#endif
}

static inline void
ptep_set_wrprotect(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
	prefetch_offset(ptep, PREFETCH_STRIDE);
#ifdef CONFIG_SMP
	ptep_wrprotect_atomic(mm, addr, ptep);
#else
	pte_t pte = *ptep;
	pte = pte_wrprotect(pte);
	set_pte_at(mm, addr, ptep, pte);
#endif
}

extern int ptep_set_access_flags(struct vm_area_struct *vma,
				 unsigned long address, pte_t *ptep,
				 pte_t entry, int dirty);

#ifdef CONFIG_MAKE_ALL_PAGES_VALID
# define ptep_clear_flush_as_valid(__vma, __address, __ptep)		\
({									\
	pte_t __pte;							\
	__pte = ptep_get_and_clear_as_valid((__vma)->vm_mm, __address, __ptep);\
	flush_tlb_page(__vma, __address);				\
	__pte;								\
})
#endif /* CONFIG_MAKE_ALL_PAGES_VALID */

#define pgd_addr_bound(addr)	(((addr) + PGDIR_SIZE) & PGDIR_MASK)
#define pud_addr_bound(addr)	(((addr) + PUD_SIZE) & PUD_MASK)
#define pmd_addr_bound(addr)	(((addr) + PMD_SIZE) & PMD_MASK)

#if defined CONFIG_TRANSPARENT_HUGEPAGE && defined CONFIG_MAKE_ALL_PAGES_VALID
# define pmdp_collapse_flush pmdp_collapse_flush
extern pmd_t pmdp_collapse_flush(struct vm_area_struct *vma,
				 unsigned long address, pmd_t *pmdp);
extern pmd_t pmdp_huge_clear_flush(struct vm_area_struct *vma,
				   unsigned long address, pmd_t *pmdp);

static inline pmd_t pmdp_huge_get_and_clear(struct mm_struct *mm,
		unsigned long address, pmd_t *pmdp)
{
# ifdef CONFIG_SMP
	u64 newval;

	newval = (test_ts_flag(TS_KEEP_PAGES_VALID)) ?
					_PAGE_INIT_VALID : 0UL;

	return __pmd(__api_xchg_return(newval, &pmdp->pmd, d, RELAXED_MB));
# else
	pmd_t pmd = *pmdp;
	pmd_clear(pmdp);
	return pmd;
# endif
}

static inline pmd_t pmdp_huge_get_and_clear_as_valid(struct mm_struct *mm,
		unsigned long addr, pmd_t *pmdp)
{
# ifdef CONFIG_SMP
	return __pmd(__api_xchg_return(_PAGE_INIT_VALID, &pmdp->pmd, d,
			RELAXED_MB));
# else
	pmd_t pmd = *pmdp;
	set_pmd_at(mm, addr, pmdp, __pmd(_PAGE_INIT_VALID));
	return pmd;
# endif
}
#endif

/* interface functions to handle some things on the PT level */
void split_simple_pmd_page(pgprot_t *ptp, pte_t *ptes[MAX_NUM_HUGE_PTES]);
void split_multiple_pmd_page(pgprot_t *ptp, pte_t *ptes[MAX_NUM_HUGE_PTES]);
void map_pud_huge_page_to_simple_pmds(pgprot_t *pmd_page, e2k_addr_t phys_page,
					pgprot_t pgprot);
void map_pud_huge_page_to_multiple_pmds(pgprot_t *pmd_page,
			e2k_addr_t phys_page, pgprot_t pgprot);

#endif	/* !(__ASSEMBLY__) */

extern void memmap_init(unsigned long size, int nid, unsigned long zone,
		unsigned long start_pfn);

#define flush_tlb_fix_spurious_fault(vma, address)	do { } while (0)

#define __HAVE_ARCH_FLUSH_PMD_TLB_RANGE
#define __HAVE_ARCH_PMD_WRITE
#define __HAVE_ARCH_PTEP_SET_ACCESS_FLAGS
#define __HAVE_ARCH_PMDP_SET_ACCESS_FLAGS
#define __HAVE_ARCH_PTE_CLEAR_NOT_PRESENT_FULL
#define __HAVE_ARCH_PTEP_MODIFY_PROT_TRANSACTION
#define __HAVE_ARCH_PTEP_TEST_AND_CLEAR_YOUNG
#define __HAVE_ARCH_PTEP_TEST_AND_CLEAR_DIRTY
#define __HAVE_ARCH_PTEP_GET_AND_CLEAR
#define __HAVE_ARCH_PTEP_SET_WRPROTECT
#define __HAVE_ARCH_PMDP_TEST_AND_CLEAR_YOUNG
#define __HAVE_ARCH_PMDP_CLEAR_FLUSH
#define __HAVE_ARCH_PMDP_GET_AND_CLEAR
#define __HAVE_ARCH_PMDP_SET_WRPROTECT
#define __HAVE_ARCH_PMDP_HUGE_CLEAR_FLUSH
#define __HAVE_ARCH_PMDP_HUGE_GET_AND_CLEAR
#define __HAVE_ARCH_MEMMAP_INIT
#define __HAVE_PFNMAP_TRACKING
#include <asm-generic/pgtable.h>

typedef enum pte_cmp {
	PTE_SAME_CMP,
	PTE_CHANGE_PFN_CMP,
	PTE_CHANGE_PROTECTS_CMP,
	PTE_CHANGE_FLAGS_CMP,
	PTE_CHANGE_FLAGS_AND_PROTECTS_CMP,
} pte_cmp_t;

static inline pte_cmp_t pte_compare(pte_t src_pte, pte_t dst_pte)
{
	pteval_t src_pte_flags;
	pteval_t dst_pte_flags;
	pteval_t src_pte_protects;
	pteval_t dst_pte_protects;

	if (pte_same(src_pte, dst_pte))
		return PTE_SAME_CMP;
	if (pte_pfn(src_pte) != pte_pfn(dst_pte))
		return PTE_CHANGE_PFN_CMP;
	src_pte_flags = pte_only_flags(src_pte);
	dst_pte_flags = pte_only_flags(dst_pte);
	src_pte_protects = pte_only_protects(src_pte);
	dst_pte_protects = pte_only_protects(dst_pte);
	if (src_pte_flags == dst_pte_flags) {
		if (src_pte_protects == dst_pte_protects)
			return PTE_SAME_CMP;
		else
			return PTE_CHANGE_PROTECTS_CMP;
	} else if (src_pte_protects == dst_pte_protects) {
		return PTE_CHANGE_FLAGS_CMP;
	} else {
		return PTE_CHANGE_FLAGS_AND_PROTECTS_CMP;
	}
}

static inline pte_t ptep_modify_prot_start(struct vm_area_struct *vma,
					   unsigned long addr,
					   pte_t *ptep)
{
	return __pte(pt_modify_prot_atomic(vma->vm_mm, addr, (pgprot_t *)ptep));
}

static inline void ptep_modify_prot_commit(struct vm_area_struct *vma,
					   unsigned long addr,
					   pte_t *ptep, pte_t old_pte, pte_t pte)
{
	__ptep_modify_prot_commit(vma, addr, ptep, pte);
}

static inline int pmdp_test_and_clear_young(struct vm_area_struct *vma,
					    unsigned long addr, pmd_t *pmdp)
{
	pmd_t pmd;

#ifdef CONFIG_SMP
	pmd_val(pmd) = pt_clear_young_atomic(vma->vm_mm, addr,
						(pgprot_t *)pmdp);
	return pmd_young(pmd);
#else
	pmd = *pmdp;
	if (!pmd_young(pmd))
		return 0;
	set_pmd_at(vma->vm_mm, addr, pmdp, pmd_mkold(pmd));
	return 1;
#endif
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static inline void pmdp_set_wrprotect(struct mm_struct *mm,
				      unsigned long addr, pmd_t *pmdp)
{
	pt_set_wrprotect_atomic(mm, addr, (pgprot_t *)pmdp);
}

#define pmdp_establish pmdp_establish
static inline pmd_t pmdp_establish(struct vm_area_struct *vma,
		unsigned long address, pmd_t *pmdp, pmd_t pmd)
{
	return __pmd(xchg_relaxed(&pmd_val(*pmdp), pmd_val(pmd)));
}

extern int pmdp_set_access_flags(struct vm_area_struct *vma,
				 unsigned long address, pmd_t *pmdp,
				 pmd_t entry, int dirty);
#else
static inline void pmdp_set_wrprotect(struct mm_struct *mm,
				      unsigned long address, pmd_t *pmdp)
{
	BUILD_BUG();
}

static inline int pmdp_set_access_flags(struct vm_area_struct *vma,
					unsigned long address, pmd_t *pmdp,
					pmd_t entry, int dirty)
{
	BUILD_BUG();
	return 0;
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

#endif /* !(_E2K_PGTABLE_H) */
