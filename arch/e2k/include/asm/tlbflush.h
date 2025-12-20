/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * The functions and defines necessary to allocate page tables.
 */

#ifndef _E2K_TLBFLUSH_H
#define _E2K_TLBFLUSH_H

#include <linux/mm_types.h>


/*
 * TLB flushing:
 *
 *  - flush_tlb_all() flushes all processes TLBs
 *  - flush_tlb_mm(mm) flushes the specified mm context TLB's
 *  - flush_tlb_page(vma, vmaddr) flushes one page
 *  - flush_tlb_range(mm, start, end) flushes a range of pages
 *
 * "local_" versions flush on the calling CPU only.
 */

/**
 * native_flush_tlb_mm_range - flush specified range from all TLU caches
 *		       (i.e. from L1D, L1I, DTLB, TLU_CACHE.PWC, TLU_CACHE.GWC)
 * @mm: contains hardware context (called ASID on other arch-es)
 * @start: start of the range to flush
 * @end: end of the range to flush
 * @stride: distance between consequential flushes
 * @levels_mask: set if there are intermediate page table levels to flush.
 *
 * Note that @levels_mask should be 0 if we want to flush only the last level.
 * For example, to flush just huge PMDs: levels_mask=0 and stride=PMD_SIZE.
 *
 * Macros are defined for convenience:
 *   FLUSH_TLB_LEVELS_ALL - flush all levels
 *   FLUSH_TLB_LEVELS_LAST - flush last level only (be it huge mapping or not)
 *   FLUSH_TLB_LEVELS_INTERMEDIATE - flush everything but the last level
 */
#define FLUSH_TLB_LEVELS_ALL	(E2K_PAGES_LEVEL_MASK | E2K_PTE_LEVEL_MASK | \
				 E2K_PMD_LEVEL_MASK | E2K_PUD_LEVEL_MASK)
#define FLUSH_TLB_LEVELS_LAST	E2K_PAGES_LEVEL_MASK
#define FLUSH_TLB_LEVELS_INTERMEDIATE	(E2K_PTE_LEVEL_MASK | \
					 E2K_PMD_LEVEL_MASK | E2K_PUD_LEVEL_MASK)
extern void native_flush_tlb_mm_range(struct mm_struct *mm,
		unsigned long start, unsigned long end,
		unsigned long stride, u32 levels_mask);
extern void native_flush_tlb_page(struct mm_struct *mm, unsigned long addr);
extern void native_flush_tlb_mm(struct mm_struct *mm);
extern void native_flush_tlb_all(void);
extern void native_flush_tlb_kernel_range(unsigned long start, unsigned long end);
extern void native_flush_tlb_kernel_range_nmi(unsigned long start, unsigned long end);

/* Linux assumes that flush_tlb_range() interface flushes
 * all levels (this may be changed in future versions in
 * which case we can pass FLUSH_TLB_LEVELS_LAST instead).
 *
 * E.g. we may be invalidating table entries as part of
 * collapsing hugepages or moving page tables. */
#define native_flush_tlb_range(mm, start, end) \
	native_flush_tlb_mm_range((mm), (start), (end), \
				  PAGE_SIZE, FLUSH_TLB_LEVELS_ALL)

#define native_flush_tlb_range_and_pgtables(mm, start, end) \
	native_flush_tlb_mm_range((mm), (start), (end), \
				  PAGE_SIZE, FLUSH_TLB_LEVELS_ALL)

#define native_flush_pmd_tlb_range(mm, start, end) \
	native_flush_tlb_mm_range((mm), (start), (end), \
				  PMD_SIZE, FLUSH_TLB_LEVELS_LAST)

#define native_flush_pud_tlb_range(mm, start, end) \
	native_flush_tlb_mm_range((mm), (start), (end), \
				  PUD_SIZE, FLUSH_TLB_LEVELS_LAST)

/*
 * Signal to all users of this mm that it has been flushed.
 * Invalid context will be updated while activating or switching to.
 *
 * Things to consider:
 *
 * 1) Clearing the whole context for CPUs to which we send the flush
 * ipi looks unnecessary, but is needed to avoid race conditions. The
 * problem is that there is a window between reading mm_cpumask() and
 * deciding which context should be set to 0. In that window situation
 * could have changed, so the only safe way is to set mm context on
 * ALL cpus to 0.
 *
 * 2) Setting it to 0 essentially means that the cpus which receive the
 * flush ipis cannot flush only a range of pages because they do not
 * know the context, so they will flush the whole mm.
 */
static inline void clear_mm_remote_context(mm_context_t *context, int cpu)
{
	int i;

#pragma loop count (NR_CPUS)
	for (i = 0; i < nr_cpu_ids; i++) {
		if (i == cpu)
			/* That being said, current CPU can still
			 * flush only the given range of pages. */
			continue;
		context->cpumsk[i] = 0;
	}
}

extern void mmu_pid_flush_tlb_mm(mm_context_t *context, bool is_active,
		cpumask_t *mm_cpumask, int cpu, bool trace_enabled);
extern void mmu_pid_flush_tlb_page(mm_context_t *context, bool is_active,
		cpumask_t *mm_cpumask, unsigned long addr, int cpu,
		bool trace_enabled);
extern void mmu_pid_flush_tlb_range(mm_context_t *context, bool is_active,
		cpumask_t *mm_cpumask, unsigned long start, unsigned long end,
		unsigned long stride, u32 levels_mask, int cpu, bool trace_enabled);

extern void generic_local_flush_tlb_mm_range(struct mm_struct *mm,
		mm_context_t *context, cpumask_t *mm_cpumask,
		unsigned long start, unsigned long end,
		unsigned long stride, u32 levels_mask, bool trace_enabled);
extern void generic_flush_tlb_mm(struct mm_struct *mm, mm_context_t *context,
		cpumask_t *mm_cpumask, bool trace_enabled);
extern void generic_flush_tlb_page(struct mm_struct *mm, mm_context_t *context,
		cpumask_t *mm_cpumask, unsigned long addr, bool trace_enabled);
extern void generic_flush_tlb_mm_range(struct mm_struct *mm, mm_context_t *context,
		cpumask_t *mm_cpumask, unsigned long start, unsigned long end,
		unsigned long stride, u32 levels_mask, bool trace_enabled);

extern void native_local_flush_tlb_mm_range(struct mm_struct *mm, unsigned long start,
		unsigned long end, unsigned long stride, u32 levels_mask);
extern void native_local_flush_tlb_page(struct mm_struct *mm, unsigned long addr);
extern void native_local_flush_tlb_mm(struct mm_struct *mm);
extern void native_local_flush_tlb_all(void);
static inline void native_local_flush_tlb_page_and_pgtables(
		struct mm_struct *mm, unsigned long uaddr)
{
	native_local_flush_tlb_mm_range(mm, uaddr, uaddr + 1,
			PAGE_SIZE, FLUSH_TLB_LEVELS_ALL);
}


#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is virtualized guest kernel */
#include <asm/kvm/guest/tlbflush.h>
# define flush_tlb_all			kvm_flush_tlb_all
# define flush_tlb_kernel_range		kvm_flush_tlb_kernel_range
# define flush_tlb_kernel_range_nmi	kvm_flush_tlb_kernel_range
# define flush_tlb_mm			kvm_flush_tlb_mm
# define flush_tlb_mm_page		kvm_flush_tlb_page
# define flush_tlb_page(vma, addr)	kvm_flush_tlb_page((vma)->vm_mm, (addr))
# define flush_tlb_mm_range		kvm_flush_tlb_mm_range
# define flush_tlb_range_and_pgtables	kvm_flush_tlb_range_and_pgtables
# define flush_tlb_range(vma, start, end) \
		kvm_flush_tlb_range((vma)->vm_mm, (start), (end))
# define flush_pmd_tlb_range(vma, start, end) \
		kvm_flush_pmd_tlb_range((vma)->vm_mm, (start), (end))
# define flush_pud_tlb_range(vma, start, end) \
		kvm_flush_pud_tlb_range((vma)->vm_mm, (start), (end))
/* local_*() versions are for flushing current CPU only.
 * A bit of an overkill: flushing whole mm instead of just current CPU... */
# define local_flush_tlb_mm_range	kvm_flush_tlb_mm_range
# define local_flush_tlb_page		kvm_flush_tlb_page
# define local_flush_tlb_mm		kvm_flush_tlb_mm
# define local_flush_tlb_page_and_pgtables kvm_flush_tlb_page_and_pgtables
# define local_flush_tlb_all() \
		pr_warn_once("%s(): try to flush whole local TLB : op 0x%lx\n", \
			     __func__, flush_op_tlb_all)
#else	/* !CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel without virtualization support */
/* or native kernel with virtualization support */
# define flush_tlb_all			native_flush_tlb_all
# define flush_tlb_kernel_range		native_flush_tlb_kernel_range
# define flush_tlb_kernel_range_nmi	native_flush_tlb_kernel_range_nmi
# define flush_tlb_mm			native_flush_tlb_mm
# define flush_tlb_mm_page		native_flush_tlb_page
# define flush_tlb_page(vma, addr)	native_flush_tlb_page((vma)->vm_mm, (addr))
# define flush_tlb_mm_range		native_flush_tlb_mm_range
# define flush_tlb_range_and_pgtables	native_flush_tlb_range_and_pgtables
# define flush_tlb_range(vma, start, end) \
		native_flush_tlb_range((vma)->vm_mm, (start), (end))
# define flush_pmd_tlb_range(vma, start, end) \
		native_flush_pmd_tlb_range((vma)->vm_mm, (start), (end))
# define flush_pud_tlb_range(vma, start, end) \
		native_flush_pud_tlb_range((vma)->vm_mm, (start), (end))
/* local_*() versions are for flushing current CPU only */
# define local_flush_tlb_mm_range	native_local_flush_tlb_mm_range
# define local_flush_tlb_page		native_local_flush_tlb_page
# define local_flush_tlb_mm		native_local_flush_tlb_mm
# define local_flush_tlb_all		native_local_flush_tlb_all
# define local_flush_tlb_page_and_pgtables \
		native_local_flush_tlb_page_and_pgtables
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#ifdef	CONFIG_KVM_HOST_MODE
#include <asm/kvm/tlbflush.h>
#endif	/* CONFIG_KVM_HOST_MODE */

#endif /* _E2K_TLBFLUSH_H */
